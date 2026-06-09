import os
import sys
import time
import asyncio
import datetime
from itertools import count
from collections import deque
from typing import Any, Awaitable, Dict, Deque, Tuple, Union, Optional, Callable, Literal, cast, overload, Coroutine, List, TYPE_CHECKING
from aioquic.quic.events import QuicEvent, StreamDataReceived, StreamReset, ConnectionTerminated, HandshakeCompleted
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import QuicErrorCode
from pathlib import Path
import traceback
import logging

from KeyisBTools import TTLDict
from gnobjects.net.objects import GNRequest, GNResponse, Url
from gnobjects.net.fastcommands import AllGNFastCommands, GNFastCommand
from gnobjects.net.domains import GNDomain
from .._crt import crt_client, ml_kem_crt_client
from .._gn_pq_quic import build_gn_pq_client_settings
from .._kdc_object import KDCObject
from ..server._datagram_enc import QuicProtocolShell, ConnectionEncryptor
from ._client_quic_shell import connect


# os.environ['OQS_INSTALL_PATH'] = str((Path(__file__).parent / ".." / "oqs").resolve())
# from ..oqs import Signature as OQSSignature, KeyEncapsulation as OQSKeyEncapsulation

if TYPE_CHECKING:
    from ..server._app import App

logger = logging.getLogger("GNServer.Client")



def _build_transport_connection_error(
    *,
    domain: str,
    source: str,
    reason: Optional[str] = None,
    error_code: Optional[int] = None,
    error_name: Optional[str] = None,
    frame_type: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
) -> GNResponse:
    payload: Dict[str, Any] = {
        'domain': domain,
        'source': source,
    }

    if reason:
        payload['reason'] = reason
    if error_code is not None:
        payload['error_code'] = error_code
    if error_name is not None:
        payload['error_name'] = error_name
    if frame_type is not None:
        payload['frame_type'] = frame_type
    if details:
        payload.update(details)

    return AllGNFastCommands.transport.ConnectionError(payload)





"""
L1 - Physical
L2 - MAC
L3 - IP
L4 - UDP
L5 - quic(packet managment)
L6 - GN(protocol managment)
"""

from ._values import _c

class AsyncClient:
    _dns_core__ipv6 = _c['dns_core__ipv6']
    _dns_core__domain = _c['dns_core__domain']

    _dns_core2__ipv6 = _c['dns_core__ipv6']
    _dns_core2__domain = _c['dns_core__domain']

    _usercoredns_ = None
    def __init__(self, server: Optional['App'] = None):
        self.server = server
        self.__dns_gn__ipv4: Optional[str] = None

        self.__current_session = {}
        self.__request_callbacks = {}
        self.__response_callbacks = {}

        self._active_connections: Dict[str, QuicClient] = {}
        self._connect_locks: Dict[str, asyncio.Lock] = {}
        self._domain_generation = 0

        self._dns_cache: TTLDict = TTLDict()
        
        self._kdc = KDCObject(self)

        self._configuration: dict = {
            'L5': {
                'connection': {
                    'connect_timeout': 10,
                },
                'disconnection': {
                    'idle_timeout': 60,
                    'ping_interval': 15,
                    'ping_check_interval': 5,
                }
            }
        }

        self._dns_inflight: Dict[str, asyncio.Future] = {}


        # First DNS core: TLS only (encType 0)
        self._kdc.setDomainEcryptionType(AsyncClient._dns_core__ipv6, 0)
        self._kdc.setDomainEcryptionType(AsyncClient._dns_core__domain, 0)

    def init(self,
             gn_crt: Union[bytes, str, Path, dict],
             requested_domains: list[str] | None = None,
             active_key_synchronization: bool = True,
             active_key_synchronization_callback: Callable[[list[str | tuple[int, int]]], list[tuple[tuple[int, int], str, bytes] | bool] | Awaitable[list[tuple[tuple[int, int], str, bytes] | bool]]] | None = None,
             active_key_synchronization_callback_domainFilter: list[str] | None = None
             ):

        if gn_crt is None:
            return

        from ..server._gnserver import GNServer as _gnserver

        self._gn_crt_data = _gnserver._get_gn_server_crt(gn_crt, self._domain) if not isinstance(gn_crt, dict) else gn_crt

        self._kdc.init(
            self._gn_crt_data,
            list(requested_domains or []),
            active_key_synchronization,
            active_key_synchronization_callback,
            active_key_synchronization_callback_domainFilter
        )


    @staticmethod
    def _consume_background_disconnect(task: asyncio.Task) -> None:
        if task.cancelled():
            return

        try:
            task.result()
        except Exception:
            logger.exception('Failed to close stale GN client connection after domain change')

    @staticmethod
    def _domain_change_runtime_error(previous_domain: Optional[str], domain: str) -> RuntimeError:
        return RuntimeError(f'Client domain changed from {previous_domain!r} to {domain!r}')

    def _disconnect_active_connections_for_domain_change(self, previous_domain: Optional[str], domain: str) -> None:
        connections = tuple(self._active_connections.values())
        if not connections:
            return

        self._active_connections.clear()

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        for connection in connections:
            connection.status = 'disconnect'
            if not connection.connect_future.done():
                connection.connect_future.set_exception(self._domain_change_runtime_error(previous_domain, domain))
            if not connection.ready.done():
                connection.ready.set_exception(self._domain_change_runtime_error(previous_domain, domain))

            if loop is not None:
                task = loop.create_task(connection.disconnect(remember_inactive=False))
                task.add_done_callback(self._consume_background_disconnect)

        if loop is None:
            logger.warning(
                'Client domain changed from %r to %r: detached %d active connections, '
                'but cannot close transports without a running event loop',
                previous_domain,
                domain,
                len(connections),
            )

    
    def setDomain(self, domain: str):
        previous_domain = getattr(self, '_domain', None)
        self._domain = domain
        if hasattr(self._kdc, '_domain'):
            self._kdc._domain = domain

        if previous_domain == domain:
            return

        self._domain_generation += 1
        self._kdc.clearInactiveTransportSessions()
        self._disconnect_active_connections_for_domain_change(previous_domain, domain)

    def setConfiguration(self, configuration: dict):
        self._configuration = configuration

    def addRequestCallback(self, callback: Callable, name: str):
        self.__request_callbacks[name] = callback

    def addResponseCallback(self, callback: Callable, name: str):
        self.__response_callbacks[name] = callback

  
    async def connect(self, request: GNRequest, restart_connection: bool = False, reconnect_wait: float = 10, keep_alive: bool = True, connection_data: dict | None = None) -> Union['QuicClient', GNResponse]:
        domain = request.url.hostname
        kdc_keyid: Optional[Tuple[int, int]] = None
        kdc_app_domain: Optional[str] = None
        if connection_data is not None:
            kdc_data = connection_data.get('kdc')
            if isinstance(kdc_data, dict):
                raw_keyid = kdc_data.get('keyid')
                if isinstance(raw_keyid, (tuple, list)) and len(raw_keyid) == 2:
                    kdc_keyid = (int(raw_keyid[0]), int(raw_keyid[1]))
                elif isinstance(raw_keyid, int):
                    kdc_keyid = (253, raw_keyid)
                if kdc_keyid is not None and (kdc_keyid[0] not in (252, 253) or kdc_keyid[1] < 0 or kdc_keyid[1] > 0xFFFFFFFFFFFFFF):
                    raise ValueError('connection_data.kdc.keyid must be (252|253, node_inc_id) with a 7-byte node_inc_id')
                raw_app_domain = kdc_data.get('app_domain')
                if isinstance(raw_app_domain, str) and raw_app_domain:
                    kdc_app_domain = raw_app_domain
        connection_key = domain if kdc_keyid is None else f'{domain}|kdc:{kdc_keyid[0]}:{kdc_keyid[1]}|app:{kdc_app_domain or ""}'
        connect_timeout = reconnect_wait or self._configuration.get('L5', {}).get('connection', {}).get('connect_timeout', 10)
        connect_lock = self._connect_locks.setdefault(connection_key, asyncio.Lock())

        async def _acquire_connect_lock() -> None:
            try:
                await asyncio.wait_for(connect_lock.acquire(), connect_timeout)
            except asyncio.TimeoutError:
                raise AllGNFastCommands.transport.SendTimeout(
                    f'Не удалось отправить запрос (таймаут соединения) с сервером {domain}'
                )

        if restart_connection:
            await _acquire_connect_lock()
            try:
                if connection_key in self._active_connections:
                    await self.disconnect(connection_key)
            finally:
                connect_lock.release()

        creator = False
        c: Optional[QuicClient] = None

        while c is None:
            current = self._active_connections.get(connection_key)
            if current is not None:
                if current._client_domain_generation != self._domain_generation:
                    await self.disconnect(connection_key, remember_inactive=False)
                    continue

                if current.status == 'active' and current._quik_core is not None:
                    return current

                if current.status == 'connecting':
                    try:
                        await asyncio.wait_for(asyncio.shield(current.connect_future), connect_timeout)
                    except asyncio.TimeoutError:
                        if self._active_connections.get(connection_key) is current:
                            await self.disconnect(connection_key)
                        raise AllGNFastCommands.transport.SendTimeout(
                            f'Не удалось отправить запрос (таймаут соединения) с сервером {domain}'
                        )
                    except asyncio.exceptions.CancelledError:
                        if self._active_connections.get(connection_key) is current:
                            await self.disconnect(connection_key)
                        raise
                    except Exception as e:
                        if self._active_connections.get(connection_key) is current:
                            await self.disconnect(connection_key)
                        if isinstance(e, (GNResponse, GNFastCommand)):
                            return e
                        raise AllGNFastCommands.transport.ConnectionError(
                            {'info': f'Не удалось подключится к серверу {domain}', 'traceback': traceback.format_exc()}
                        )

                    if current.status == 'active' and current._quik_core is not None:
                        return current

                    if current.status == 'disconnect':
                        raise AllGNFastCommands.transport.ConnectionError(
                            {'info': f'Не удалось подключится к серверу {domain}', 'traceback': traceback.format_exc()}
                        )

                    if self._active_connections.get(connection_key) is current:
                        await self.disconnect(connection_key)
                    raise AllGNFastCommands.transport.ConnectionError(
                        {'info': f'Не удалось подключится к серверу {domain}', 'traceback': traceback.format_exc()}
                    )

                await _acquire_connect_lock()
                try:
                    if self._active_connections.get(connection_key) is current:
                        self._active_connections.pop(connection_key, None)
                finally:
                    connect_lock.release()
                continue

            await _acquire_connect_lock()
            try:
                current = self._active_connections.get(connection_key)
                if current is not None:
                    continue

                c = QuicClient(self, domain, self._domain_generation)
                c._connection_key = connection_key
                c._kdc_keyid = kdc_keyid
                c._kdc_app_domain = kdc_app_domain
                self._active_connections[connection_key] = c
                creator = True
            finally:
                connect_lock.release()

        if not creator:
            raise AllGNFastCommands.transport.ConnectionError({'info': f'Не удалось подключится к серверу {domain}', 'traceback': traceback.format_exc()})

        if c._client_domain_generation != self._domain_generation:
            await c.disconnect(remember_inactive=False)
            raise AllGNFastCommands.transport.ConnectionError(
                {'source': 'client_domain_changed', 'domain': domain, 'client_domain': getattr(self, '_domain', None)}
            )

        data = None
        if connection_data is not None:
            if 'dns' in connection_data:
                data = cast(str, connection_data['dns']['ip:port'])

        if data is None:
            data = await self.getDNS(domain, host=domain if request.url.isIp else None)

        data = Url.ipv6_with_port_to_ipv6_and_port(data)
        logger.info(f'Connecting to {domain} dns: {data} (restart_connection={restart_connection}, reconnect_wait={reconnect_wait}, keep_alive={keep_alive})')

        # if data[0].startswith('::ffff:'):
        #     data = (data[0][7:], data[1])

        def f(domain):
            if domain in self._active_connections:
                self._active_connections.pop(domain)

        c._disconnect_signal = f # type: ignore

        try:
            if c._client_domain_generation != self._domain_generation:
                raise RuntimeError('Client domain changed before QUIC connect')
            await asyncio.wait_for(c.connect(data[0], data[1], keep_alive=keep_alive), connect_timeout)
            if c._client_domain_generation != self._domain_generation:
                raise RuntimeError('Client domain changed during QUIC connect')
        except asyncio.exceptions.TimeoutError:
            await self.disconnect(connection_key)
            raise AllGNFastCommands.transport.QuicHandshakeTimeout(f'Не удалось подключится к серверу {domain} (таймаут рукопожатия)')
        except asyncio.exceptions.CancelledError:
            await self.disconnect(connection_key)
            raise
        except Exception as e:
            await self.disconnect(connection_key)
            if isinstance(e, (GNResponse, GNFastCommand)):
                return e
            raise AllGNFastCommands.transport.ConnectionError({'info': f'Не удалось подключится к серверу {domain}', 'traceback': traceback.format_exc()})

        try:
            await c.connect_future
        except Exception as e:
            await self.disconnect(connection_key)
            if isinstance(e, (GNResponse, GNFastCommand)):
                return e
            raise

        return c

    async def disconnect(self, domain, remember_inactive: bool = True):
        connection = self._active_connections.get(domain)
        if connection is None:
            prefix = f'{domain}|kdc:'
            for key, active_connection in list(self._active_connections.items()):
                if isinstance(key, str) and key.startswith(prefix):
                    await active_connection.disconnect(remember_inactive=remember_inactive)
                    if self._active_connections.get(key) is active_connection:
                        self._active_connections.pop(key, None)
            return
        
        await connection.disconnect(remember_inactive=remember_inactive)
        if self._active_connections.get(domain) is connection:
            self._active_connections.pop(domain, None)


    def _return_token(self, bigToken: str, s: bool = True) -> str:
        return bigToken[:128] if s else bigToken[128:]

    async def _resolve_requests_transport(self, request: GNRequest) -> GNRequest:
        
        if request.transportObject.routeProtocol.dev:
            if request.cookies is not None:
                data: Optional[dict] = request.cookies.get('gn', {}).get('request', {}).get('transport', {}).get('::dev')
                if data is not None:
                    if 'netstat' in data:
                        if 'way' in data['netstat']:
                            if 'data' not in data['netstat']['way']:
                                data['netstat']['way']['data'] = []



                #     data['params']['logs']['data'] = []
                #     data['params']['data']['data'] = {}
                #     request._devDataLog = data['params']['logs']['data']
                #     request._devDataLogLevel = _log_levels[data['params']['logs']['data']]
                #     request._devData = data['params']['data']['data']
                #     request._devDataRange = data['params']['range']

        return request

    async def request(self, request: GNRequest, keep_alive: bool = True, restart_connection: bool = False, reconnect_wait: float = 10, *, only_request: bool = False, connection_data: dict | None = None, return_on_response_header: bool = False) -> GNResponse:
        if not isinstance(request, GNRequest):
            raise TypeError(f'AsyncClient.request expects GNRequest, got {type(request).__name__}')

        logger.debug(f'Request: {request.method} {request.url}')

        if isinstance(request, GNRequest):
            
            request = await self._resolve_requests_transport(request)
            try:
                c = await self.connect(request, restart_connection, reconnect_wait, keep_alive=keep_alive, connection_data=connection_data)
            except BaseException as e:
                if isinstance(e, asyncio.CancelledError):
                    raise
                if isinstance(e, (GNResponse, GNFastCommand)):
                    return e
                else:
                    return GNResponse(str(e), payload=traceback.format_exc())

            if isinstance(c, GNResponse):
                return c

            for f in self.__request_callbacks.values():
                asyncio.create_task(f(request))
            try:
                r = await c.asyncRequest(request, only_request=only_request, return_on_response_header=return_on_response_header)
            except BaseException as e:
                if isinstance(e, asyncio.CancelledError):
                    raise
                if isinstance(e, (GNResponse, GNFastCommand)):
                    r = e
                else:
                    r = AllGNFastCommands.transport.ConnectionError({
                        'source': 'client_request_async_request',
                        'exception_type': type(e).__name__,
                        'exception': str(e),
                        'traceback': traceback.format_exc(),
                    })

            # retry_connect_request = (
            #     isinstance(r, GNResponse)
            #     and not only_request
            #     and request.url.path == '/gn/connect'
            #     and (
            #         r.command.transport.ReceiveTimeout
            #         or r.command.transport.ConnectionError
            #         or r.command.transport.SocketClosed
            #     )
            # )

            # if retry_connect_request:
            #     logger.warning(
            #         f"Retrying {request.method} {request.url} after transport failure: {r.command}"
            #     )
            #     try:
            #         c = await self.connect(
            #             request,
            #             restart_connection=True,
            #             reconnect_wait=reconnect_wait,
            #             keep_alive=keep_alive,
            #         )
            #         r = await c.asyncRequest(request, only_request=only_request)
            #     except BaseException as e:
            #         if isinstance(e, (GNResponse, GNFastCommand)):
            #             r = e
            #         else:
            #             r = GNResponse(str(e), payload=traceback.format_exc())

            logger.info(f'[<] Response: {request.method} {request.url} -> {r.command}')

            for f in self.__response_callbacks.values():
                asyncio.create_task(f(r))

            return r # type: ignore
        
    async def getDNS(self, domain: str, use_cache: bool = True, keep_alive: bool = False, host: Optional[str] = None) -> str:

        if domain in self._dns_inflight:
            return await self._dns_inflight[domain]

        fut = asyncio.get_running_loop().create_future()
        self._dns_inflight[domain] = fut

        try:
            r = await self._get_dns_resolve(domain, use_cache=use_cache, keep_alive=keep_alive, host=host)
            fut.set_result(r)
            return r
        except Exception as e:
            fut.set_exception(e)
            raise
        finally:
            self._dns_inflight.pop(domain, None)


    async def _get_dns_resolve(self, domain: str, use_cache: bool = True, keep_alive: bool = False, host: Optional[str] = None) -> str:

        if host is not None:
            return Url.ipv4_with_port_to_ipv6_with_port(host)

        if AsyncClient._usercoredns_ is not None:
            p = AsyncClient._usercoredns_
            AsyncClient._usercoredns_ = None
            self._kdc.setDomainEcryptionType(AsyncClient._dns_core__domain, 0)
            d: str = await self.getDNS(p, use_cache=False, keep_alive=False)

            AsyncClient._dns_core__domain = p
            AsyncClient._dns_core__ipv6 = d


        _dns_core__domain = AsyncClient._dns_core__domain
        _dns_core__ipv6 = AsyncClient._dns_core__ipv6

        if domain in (self._kdc._kdc_domain, self._kdc._second_kdc_domain):
            _dns_core__domain = AsyncClient._dns_core2__domain
            _dns_core__ipv6 = AsyncClient._dns_core2__ipv6



        if use_cache:
            result = self._dns_cache.get(domain)
            if result is not None:
                return result
            
        if domain.count(':') == 1: # it's ipv4 with port 100%
            return Url.ipv4_with_port_to_ipv6_with_port(domain)
        elif domain.count(':') > 1 and domain.count(']') == 0: # it's ipv6 without port
            return domain
        elif domain.count(':') > 1 and domain.count(']') == 1: # it's ipv6 with port
            return domain

        if domain == _dns_core__domain:
            return _dns_core__ipv6

        if domain == 'api.dns.gn':
            if self.__dns_gn__ipv4 is None:
                a = await self._get_dns_resolve('!api.dns.gn')
                if not isinstance(a, str):
                    return a
                else:
                    self.__dns_gn__ipv4 = a
            return self.__dns_gn__ipv4
        elif domain.startswith('!'):
            domain = domain[1:]

        is_dns_core = GNDomain.isSys(domain) or GNDomain.isCore(domain)
        if not is_dns_core:
            if self.__dns_gn__ipv4 is None:
                a = await self._get_dns_resolve('api.dns.gn')
                if not isinstance(a, str):
                    return a
                else:
                    self.__dns_gn__ipv4 = a


        if is_dns_core:
            domain_dns = _dns_core__domain
            if domain in (self._kdc._kdc_domain, self._kdc._second_kdc_domain):
                domain_dns = _dns_core__ipv6
        else:
            domain_dns = 'api.dns.gn'

        r1 = await self.request(GNRequest('get', Url(f'gn://{domain_dns}/getIp?d={domain}'), payload=domain), keep_alive=keep_alive)

        if not r1.command.ok:
            raise r1

        r1_data = await r1.payload
        if r1_data is None:
            raise AllGNFastCommands.transport.ConnectionError('DNS payload not fully received')

        result = Url.ip_and_port_to_ipv6_with_port(r1_data['ip'], r1_data['port']) # type: ignore
        

        self._dns_cache.set(domain, result, r1_data.get('ttl', 60)) # type: ignore

        return result
    
    async def _get_gn_dns_request(self, domain: str, keep_alive: bool = False) -> str:

        raise NotImplementedError


class RawQuicClient(QuicProtocolShell):

    def __init__(self, quic: QuicConnection, datagramEndpoint, client: 'QuicClient', stream_handler):
        super().__init__(quic, datagramEndpoint=datagramEndpoint, client=True, stream_handler=stream_handler)

        # Preserve a typed reference to QuicClient. The base class stores a bool
        # in self._client to mark client mode, so this assignment must happen after super().__init__.
        self._QuicClient = client

        self.quicClient: QuicClient = None # type: ignore

        self._queue_sys: Deque[Tuple[int, bytes, bool]] = deque()
        self._queue_user: Deque[Tuple[int, bytes, bool]] = deque()

        self._inflight: Dict[int, Union[asyncio.Future, asyncio.Queue[Optional[GNResponse]]]] = {}
        self._inflight_streams: Dict[int, Dict[str, Any]] = {}
        self._buffer: Dict[Union[int, str], bytearray] = {}
        self._timed_out_streams: set[int] = set()

        self._last_activity = time.time()
        self._running = True
        self._ping_id_gen = count(1)

        self._connection_upgrades: List[str] = []

    def _activity(self):
        self._last_activity = time.time()

    async def _keepalive_loop(self):
        while self._running:
            await asyncio.sleep(self.quicClient._client._configuration.get('L5', {}).get('disconnection', {}).get('ping_check_interval', 5))
            idle_time = time.time() - self._last_activity
            if idle_time >= self.quicClient._client._configuration.get('L5', {}).get('disconnection', {}).get('ping_interval', 15):
                self._quic.send_ping(next(self._ping_id_gen))
                self.transmit()
                self._last_activity = time.time()

    def on_prequic_error(self, error_code: int, expected_enc_type: int) -> None:
        payload = {
            'domain': self._QuicClient.domain,
            'prequic_error_code': error_code,
            'expected_encryption_type': expected_enc_type,
        }

        if error_code == 1:  # DifferentEncryptionType
            error = AllGNFastCommands.cors.DifferentEncryptionType({
                'data': {'expected_encryption_type': expected_enc_type}
            })
        elif error_code == 2:  # EncryptionKeySynchronization
            error = AllGNFastCommands.transport.EncryptionKeySynchronization(payload)
        elif error_code == 3:  # UnsupportedKeyType
            error = AllGNFastCommands.transport.UnsupportedKeyType(payload)
        else:
            error = AllGNFastCommands.transport.TransportProtocolError(payload)

        fut = self._QuicClient.connect_future
        if not fut.done():
            fut.set_exception(error)

        waiter = getattr(self, '_connected_waiter', None)
        if waiter is not None:
            self._connected_waiter = None
            if not waiter.done():
                waiter.set_exception(error)
                self._QuicClient._consume_future_exception(waiter)

        for inflight in list(self._inflight.values()):
            if isinstance(inflight, asyncio.Future) and not inflight.done():
                inflight.set_exception(error)
                self._QuicClient._consume_future_exception(inflight)
        self._inflight.clear()

        self.stop()
        self.close(error_code=QuicErrorCode.NO_ERROR, reason_phrase=f'prequic error {error_code}')
        self._closed.set()

    def stop(self):
        self._running = False

    def _feed_incoming_request(self, stream_id: int, data: bytes, end_stream: bool) -> Optional[GNRequest]:
        state = self._inflight_streams.get(stream_id)

        if state is None:
            buf = self._buffer.setdefault(stream_id, bytearray())
            buf.extend(data)

            header = GNRequest.try_deserialize_header(bytes(buf))
            if header is None:
                if end_stream:
                    if len(buf) > 0:
                        logger.warning(f'Ignoring incomplete GNRequest header on closed stream {stream_id} ({len(buf)} bytes buffered)')
                    self._buffer.pop(stream_id, None)
                return None

            request, payload_offset, payload_length = header
            state = {
                'message': request,
                'header_emitted': True,
            }

            payload_tail = bytes(buf[payload_offset:])
            if payload_tail:
                request._feedIncomingPayload(payload_tail)

            self._buffer.pop(stream_id, None)
            self._inflight_streams[stream_id] = state

            if end_stream:
                request._finishIncomingPayload(True)
                self._inflight_streams.pop(stream_id, None)

            return request

        request = cast(GNRequest, state['message'])
        if data:
            request._feedIncomingPayload(data)

        if end_stream:
            request._finishIncomingPayload(True)
            self._inflight_streams.pop(stream_id, None)

        return None

    def _feed_incoming_response(self, stream_id: int, data: bytes, end_stream: bool) -> Optional[GNResponse]:
        state = self._inflight_streams.get(stream_id)

        if state is None:
            buf = self._buffer.setdefault(stream_id, bytearray())
            buf.extend(data)

            header = GNResponse.try_deserialize_header(bytes(buf))
            if header is None:
                if end_stream:
                    if len(buf) > 0:
                        logger.warning(f'Ignoring incomplete GNResponse header on closed stream {stream_id} ({len(buf)} bytes buffered)')
                    self._buffer.pop(stream_id, None)
                return None

            response, payload_offset, payload_length = header
            trailing = bytes(buf[payload_offset:])

            state = {
                'message': response,
                'header_emitted': False,
            }

            if trailing:
                response._feedIncomingPayload(trailing)

            self._buffer.pop(stream_id, None)
            self._inflight_streams[stream_id] = state

            if end_stream:
                response._finishIncomingPayload(True)
                self._inflight_streams.pop(stream_id, None)
                self._inflight.pop(stream_id, None)

            state['header_emitted'] = True
            return response

        response = cast(GNResponse, state['message'])
        if data:
            response._feedIncomingPayload(data)

        if end_stream:
            response._finishIncomingPayload(True)
            self._inflight_streams.pop(stream_id, None)
            self._inflight.pop(stream_id, None)

        return None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            logger.debug(
                f'HandshakeCompleted for {self._QuicClient.domain}: '
                f'alpn={event.alpn_protocol} resumed={event.session_resumed} '
                f'early_data={event.early_data_accepted}'
            )
            self.setDefault_max_datagram_size()
            domain = self._QuicClient.domain
            self._apply_gn_pq_session_root(domain)
            return

        if isinstance(event, StreamDataReceived):
            if event.stream_id in self._timed_out_streams:
                if event.end_stream:
                    self._timed_out_streams.discard(event.stream_id)
                return

            handler = self._inflight.get(event.stream_id)
            if handler is None:
                if self._QuicClient._client.server is None:
                    return
                request = self._feed_incoming_request(event.stream_id, event.data, event.end_stream)
                if request is None:
                    return

                request.client._data['domain'] = self._QuicClient.domain

                network_paths = getattr(self._quic, "_network_paths", None)
                request.client._data['remote_addr'] = network_paths[0].addr if network_paths else None
                request.stream_id = event.stream_id   # type: ignore
                request._assembly_server()

                self._loop.create_task(self._QuicClient._client.server.dispatchRequest(request))
            else:
                if not isinstance(handler, asyncio.Queue):
                    try:
                        response = self._feed_incoming_response(event.stream_id, event.data, event.end_stream)
                    except Exception as exc:
                        self._inflight.pop(event.stream_id, None)
                        self._buffer.pop(event.stream_id, None)
                        self._inflight_streams.pop(event.stream_id, None)
                        if not handler.done():
                            handler.set_exception(exc)
                        return
                    if response is None:
                        return
                    if not handler.done():
                        handler.set_result(response)
                else:
                    raise NotImplementedError
                

        # ─── RESET ──────────────────────────────────────────
        elif isinstance(event, StreamReset):
            handler = self._inflight.pop(event.stream_id, None)
            state = self._inflight_streams.pop(event.stream_id, None)
            if state is not None:
                message = cast(Union[GNRequest, GNResponse], state['message'])
                message._finishIncomingPayload(False)
            self._buffer.pop(event.stream_id, None)
            if handler is None:
                return
            if isinstance(handler, asyncio.Queue):
                handler.put_nowait(None)
            else:
                if not handler.done():
                    handler.set_exception(RuntimeError("stream reset"))


        elif isinstance(event, ConnectionTerminated):
            client_ref = self.quicClient if self.quicClient is not None else self._QuicClient

            try:
                error_name = QuicErrorCode(event.error_code).name
            except Exception:
                error_name = 'UNKNOWN'

            logger.warning(
                f'ConnectionTerminated for {client_ref.domain}: '
                f'code={event.error_code}({error_name}) frame_type={event.frame_type} '
                f'reason={event.reason_phrase!r}'
            )

            transport_error_details = {
                'event': 'ConnectionTerminated',
            }
            transport_error = _build_transport_connection_error(
                domain=client_ref.domain,
                source='quic_connection_terminated',
                reason=event.reason_phrase or None,
                error_code=event.error_code,
                error_name=error_name,
                frame_type=event.frame_type,
                details=transport_error_details,
            )

            for handler in self._inflight.values():
                if isinstance(handler, asyncio.Queue):
                    handler.put_nowait(None)
                else:
                    if not handler.done():
                        handler.set_exception(transport_error)
                        client_ref._consume_future_exception(handler)  # Fix 4: гасим необработанную фьючу

            for state in self._inflight_streams.values():
                message = cast(Union[GNRequest, GNResponse], state['message'])
                message._finishIncomingPayload(False)
            
            self.stop()
            
            asyncio.create_task(client_ref.disconnect())



    def _schedule_flush(self):
        self.transmit()
        self._activity()

    async def _resolve_requests_transport(self, request: GNRequest):
        
            if request.transportObject.routeProtocol.dev:
                if request.cookies is not None:
                    data: Optional[dict] = request.cookies.get('gn', {}).get('request', {}).get('transport', {}).get('::dev')
                    if data is not None:
                        if 'netstat' in data:
                            if 'way' in data['netstat']:
                                data['netstat']['way']['data'].append({
                                    'object': 'GNClient',
                                    'step': '1',
                                    'type': 'L5',
                                    'action': 'send',
                                    'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                    'route': str(request.route),
                                    'method': request.method,
                                    'url': str(request.url),
                                })



    async def request(self, request: GNRequest, only_request: bool = False, return_on_response_header: bool = False):
    
        await self._resolve_requests_transport(request)

        sid = self._quic.get_next_available_stream_id()

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        if not only_request:
            self._inflight[sid] = fut

        header = request.serializeHeader()
        has_payload = request.hasPayload

        def _reset_outgoing_stream_after_cleanup(source: str) -> None:
            if not has_payload:
                return
            try:
                self._quic.reset_stream(sid, QuicErrorCode.INTERNAL_ERROR)
                self._schedule_flush()
            except Exception:
                logger.debug(f'{source}: failed to reset request stream {sid} after cleanup')

        async def _send_request() -> None:
            # header уже поставлен в поток синхронно (ниже, до create_task) — здесь только тело.
            stream_finished = False
            try:
                await self._drain_stream_send_buffer(sid)

                if not has_payload:
                    return

                async for chunk in request.iterSerializedPayload(self.datagramEndpoint.DEPConfig.iter_payload_chunk_size):
                    self._quic.send_stream_data(sid, chunk, end_stream=False)
                    self._schedule_flush()
                    await self._drain_stream_send_buffer(sid)

                self._quic.send_stream_data(sid, b'', end_stream=True)
                self._schedule_flush()
                stream_finished = True
                await self._drain_stream_send_buffer(sid)
            except BaseException:
                if not stream_finished:
                    _reset_outgoing_stream_after_cleanup('request_body_send_failed')
                raise

        data_ready = False
        data = None
        send_task: Optional[asyncio.Task[None]] = None
        response_header_deadline = loop.time() + 15.0 if return_on_response_header and not only_request else None

        try:
            # Резервируем QUIC-поток СИНХРОННО: ставим header в поток до любого await/
            # create_task. get_next_available_stream_id() не резервирует id до первой записи,
            # поэтому без этого конкурентный request() на том же соединении получит тот же
            # stream_id -> два запроса сольются в один поток и один молча потеряется (таймаут).
            self._quic.send_stream_data(sid, header, end_stream=not has_payload)
            self._schedule_flush()

            if return_on_response_header and not only_request:
                send_task = asyncio.create_task(_send_request())

                def _consume_send_task_exception(task: asyncio.Task[None]) -> None:
                    if task.cancelled():
                        return
                    try:
                        task.result()
                    except Exception:
                        logger.error(f'Request body send failed after response header on stream {sid}:\n{traceback.format_exc()}')

                send_task.add_done_callback(_consume_send_task_exception)
                timeout = None if response_header_deadline is None else max(0.0, response_header_deadline - loop.time())
                done, _ = await asyncio.wait({fut, send_task}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    if not send_task.done():
                        send_task.cancel()
                    _reset_outgoing_stream_after_cleanup('response_header_timeout')
                    self._inflight.pop(sid, None)
                    self._buffer.pop(sid, None)
                    state = self._inflight_streams.pop(sid, None)
                    if state is not None:
                        cast(Union[GNRequest, GNResponse], state['message'])._finishIncomingPayload(False)
                    self._timed_out_streams.add(sid)
                    if len(self._timed_out_streams) > 8192:
                        self._timed_out_streams.clear()
                    logger.warning(f'Timeout waiting for response header on stream {sid}')
                    return AllGNFastCommands.transport.ReceiveTimeout()

                if fut in done:
                    data = fut.result()
                    data_ready = True
                    if isinstance(data, GNResponse):
                        data._request_send_task = send_task
                else:
                    await send_task
            else:
                await _send_request()
        except asyncio.CancelledError:
            if isinstance(send_task, asyncio.Task) and not send_task.done():
                send_task.cancel()
            _reset_outgoing_stream_after_cleanup('request_cancelled')
            self._inflight.pop(sid, None)
            self._buffer.pop(sid, None)
            state = self._inflight_streams.pop(sid, None)
            if state is not None:
                cast(Union[GNRequest, GNResponse], state['message'])._finishIncomingPayload(False)
            self._timed_out_streams.add(sid)
            if len(self._timed_out_streams) > 8192:
                self._timed_out_streams.clear()
            raise
        except Exception:
            _reset_outgoing_stream_after_cleanup('request_failed')
            self._inflight.pop(sid, None)
            self._buffer.pop(sid, None)
            state = self._inflight_streams.pop(sid, None)
            if state is not None:
                cast(Union[GNRequest, GNResponse], state['message'])._finishIncomingPayload(False)
            exc = sys.exc_info()[1]
            if isinstance(exc, GNResponse):
                return exc
            logger.error(traceback.format_exc())
            return _build_transport_connection_error(
                domain=self._QuicClient.domain,
                source='request_send_failed',
                details={
                    'exception_type': type(exc).__name__ if exc is not None else 'UnknownError',
                    'exception': str(exc) if exc is not None and str(exc) else None,
                },
            )

        if only_request:
            return AllGNFastCommands.transport.NoResponse()

        if not data_ready:
            logger.debug(f'Waiting for response on stream {sid}...')
            try:
                response_timeout = 30.0
                if response_header_deadline is not None:
                    response_timeout = max(0.0, response_header_deadline - loop.time())
                    if response_timeout <= 0.0:
                        raise asyncio.exceptions.TimeoutError()

                data = await asyncio.wait_for(fut, response_timeout)
                data_ready = True
                logger.debug(f'Response received on stream {sid}')
            except asyncio.exceptions.TimeoutError:
                self._inflight.pop(sid, None)
                self._buffer.pop(sid, None)
                state = self._inflight_streams.pop(sid, None)
                if state is not None:
                    cast(Union[GNRequest, GNResponse], state['message'])._finishIncomingPayload(False)
                self._timed_out_streams.add(sid)
                if len(self._timed_out_streams) > 8192:
                    self._timed_out_streams.clear()
                logger.warning(f'Timeout waiting for response on stream {sid}')
                return AllGNFastCommands.transport.ReceiveTimeout()
            except asyncio.CancelledError:
                self._inflight.pop(sid, None)
                self._buffer.pop(sid, None)
                state = self._inflight_streams.pop(sid, None)
                if state is not None:
                    cast(Union[GNRequest, GNResponse], state['message'])._finishIncomingPayload(False)
                self._timed_out_streams.add(sid)
                if len(self._timed_out_streams) > 8192:
                    self._timed_out_streams.clear()
                raise
            except Exception:
                self._inflight.pop(sid, None)
                self._buffer.pop(sid, None)
                state = self._inflight_streams.pop(sid, None)
                if state is not None:
                    cast(Union[GNRequest, GNResponse], state['message'])._finishIncomingPayload(False)
                self._timed_out_streams.add(sid)
                if len(self._timed_out_streams) > 8192:
                    self._timed_out_streams.clear()
                exc = sys.exc_info()[1]
                if isinstance(exc, GNResponse):
                    return exc
                logger.error(traceback.format_exc())
                return _build_transport_connection_error(
                    domain=self._QuicClient.domain,
                    source='request_wait_failed',
                    details={
                        'exception_type': type(exc).__name__ if exc is not None else 'UnknownError',
                        'exception': str(exc) if exc is not None and str(exc) else None,
                    },
                )
        
        if data is None:
            return AllGNFastCommands.transport.ConnectionError()

        if isinstance(data, GNResponse):
            return data
        
        logger.error(f'Unexpected response type on stream {sid}: {type(data)!r}')
        return _build_transport_connection_error(
            domain=self._QuicClient.domain,
            source='unexpected_response_type',
            details={'response_type': type(data).__name__},
        )
        
    # def _upgradeConnection(self, alg: str, later: bool = True) -> None:
    #     if alg not in self._connection_upgrades:
    #         self._connection_upgrades.append(alg)
    #         if not later:
    #             self.__upgradeConnection(alg)

    # def __upgradeConnection(self, alg:str) -> None:
    #     if alg == 'ML-KEM:M1':
    #         kem = OQSKeyEncapsulation("ML-KEM-1024")
    #         ciphertext, shared_secret = kem.encap_secret(ml_kem_crt_client)
    #         kem.free()
        

class QuicClient:
    """Обёртка‑фасад над RawQuicClient."""

    @staticmethod
    def _consume_future_exception(fut: asyncio.Future) -> None:
        if fut.cancelled():
            return
        try:
            fut.exception()
        except Exception:
            return

    def __init__(self, Client: AsyncClient, domain: str, client_domain_generation: int):
        self._client = Client
        self.domain = domain
        self._connection_key = domain
        self._kdc_keyid: Optional[Tuple[int, int]] = None
        self._kdc_app_domain: Optional[str] = None
        self._client_domain_generation = client_domain_generation
        self._quik_core: Optional[RawQuicClient] = None
        self._client_cm = None
        self._disconnect_signal = None

        self.status: Literal['active', 'connecting', 'disconnect'] = 'connecting'

        self.connect_future = asyncio.get_event_loop().create_future()
        self.connect_future.add_done_callback(self._consume_future_exception)

        self.ready = asyncio.get_running_loop().create_future()
        self.ready.add_done_callback(self._consume_future_exception)

    async def connect(self, ip: str, port: int, keep_alive: bool = True):
        if self._client_domain_generation != self._client._domain_generation:
            raise RuntimeError('Client domain changed before QUIC connect')

        self.status = 'connecting'
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["gn:backend"])
        cfg.load_verify_locations(cadata=crt_client)
        cfg.idle_timeout = self._client._configuration.get('L5', {}).get('disconnection', {}).get('idle_timeout', 60)

        target_ipv6 = Url.ip_and_port_to_ipv6_with_port(ip, port)
        is_ip_connection = self.domain == target_ipv6

        # Determine encryption type: 0=TLS, 1=KDC+PQ+TLS, 2=PQ+TLS
        if self._client._kdc.getDomainEcryptionType(self.domain) is not None:
            encType = self._client._kdc.getDomainEcryptionType(self.domain)
        else:
            encType = 2 if is_ip_connection else 1
            self._client._kdc.setDomainEcryptionType(self.domain, encType)

        if encType == 1 and self._client.server is not None:
            established_enc_type = None
            confirmed_keyid = self._client._kdc.getKeyIdByDomain(self.domain)
            if confirmed_keyid is not None and self._client._kdc.getKey(confirmed_keyid) is not None:
                established_enc_type = await self._client.server.DEPConfig.getEstablishedEncryptionTypeForDomain(self.domain)

            if established_enc_type is None and not await self._client.server.DEPConfig.isKDCAllowedForDomain(self.domain):
                raise AllGNFastCommands.transport.PolicyDenied({
                    'policy': 'kdc_allowed_domains',
                    'domain': self.domain,
                    'reason': 'KDC bootstrap disabled for domain until GN QUIC handshake key-upgrade is enabled',
                })

        kdc_lookup: Union[str, Tuple[int, int]] = self._kdc_keyid if self._kdc_keyid is not None else self.domain
        if encType == 1:
            await self._client._kdc.requestKeyIfNotExist(kdc_lookup)

        gn_pq_kdc_key = None
        if encType == 1:
            try:
                gn_pq_kdc_key = self._client._kdc.getKey(kdc_lookup)
            except Exception:
                gn_pq_kdc_key = None

        if encType == 0:
            gn_pq_client_settings = None
        elif encType == 1:
            gn_pq_client_settings = build_gn_pq_client_settings(
                self.domain,
                kdc_key=gn_pq_kdc_key,
                client_domain=getattr(self._client, '_domain', None),
                client_gn_crt=getattr(self._client, '_gn_crt_data', None),
            )
        else:  # encType >= 2 (PQ + TLS, no KDC)
            gn_pq_client_settings = build_gn_pq_client_settings(
                self.domain,
                kdc_key=None,
                accept_any_server_domain=True,
                client_domain=getattr(self._client, '_domain', None),
                client_gn_crt=getattr(self._client, '_gn_crt_data', None),
            )

        logger.debug(
            f"Connect setup domain={self.domain} target={ip}:{port} encType={encType} "
            f"is_ip_connection={is_ip_connection} "
            f"server_name={cfg.server_name!r} gn_pq={'on' if gn_pq_client_settings is not None else 'off'} "
            f"kdc_key={'set' if gn_pq_kdc_key is not None else 'none'}"
        )

        self._client_cm = connect(
            self,
            ip,
            port,
            self.domain,
            configuration=cfg,
            create_protocol=RawQuicClient,
            wait_connected=True,
            encType=encType,  # type: ignore
            gn_pq_client_settings=gn_pq_client_settings,
        )

        try:
            self._quik_core = await self._client_cm.__aenter__() # type: ignore
            self._quik_core.quicClient = self
            if self._client_domain_generation != self._client._domain_generation:
                raise RuntimeError('Client domain changed during QUIC connect')


            self.status = 'active'


            if not self.ready.done():
                self.ready.set_result(True)

            if keep_alive:
                asyncio.create_task(self._quik_core._keepalive_loop())

            self.status = 'active'
            if not self.connect_future.done():
                self.connect_future.set_result(True)
        except Exception as e:
            logger.error(f'Error connecting: {e}')
            if not self.connect_future.done() and isinstance(e, (GNResponse, GNFastCommand)):
                self.connect_future.set_exception(e)
            if not self.connect_future.done():
                self.connect_future.set_exception(AllGNFastCommands.transport.ConnectionError({'info': f'Не удалось подключится к серверу {self.domain}', 'traceback': traceback.format_exc()}))
            await self._client_cm.__aexit__(None, None, None)

    async def disconnect(self, remember_inactive: bool = True):
        self.status = 'disconnect'
        
        if self._quik_core is not None:
            try:
                if remember_inactive:
                    self._quik_core.datagramEndpoint.markProtocolInactive(self._quik_core)
            except Exception:
                pass

            self._quik_core.stop()
        

        if self._disconnect_signal is not None:
            self._disconnect_signal(self._connection_key)
        

        if self._quik_core is not None:


            for fut in self._quik_core._inflight.values():
                if isinstance(fut, asyncio.Queue):
                    del fut
                else:
                    if not fut.done():
                        fut.set_exception(Exception())



            self._quik_core.close()
            await self._quik_core.wait_closed()
            self._quik_core = None

            if self._client_cm is not None:
                await self._client_cm.__aexit__(None, None, None)
                self._client_cm = None



    async def asyncRequest(self, request: GNRequest, only_request: bool = False, return_on_response_header: bool = False):
        if self._client_domain_generation != self._client._domain_generation:
            await self.disconnect(remember_inactive=False)
            raise RuntimeError('Client domain changed before request send')

        if self.status != 'active':
            await self.ready
            if self.status != 'active':
                raise RuntimeError("Connection not active")

        resp = await self._quik_core.request(request, only_request=only_request, return_on_response_header=return_on_response_header)

        # After transport-level timeout/errors the current QUIC session can become stale.
        # Drop it so the next request reconnects instead of reusing a broken session.
        if isinstance(resp, GNResponse):
            if resp.command.transport and not resp.command.transport.NoResponse:
                logger.warning(
                    f"Transport session degraded for {self.domain}: {resp.command}. Reconnecting on next request."
                )
                await self.disconnect()

        return resp
