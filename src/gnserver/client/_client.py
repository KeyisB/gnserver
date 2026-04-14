import os
import sys
import time
import asyncio
import datetime
from itertools import count
from collections import deque
from typing import Any, Awaitable, Dict, Deque, Tuple, Union, Optional, AsyncGenerator, Callable, Literal, AsyncIterable, cast, overload, Coroutine, List, TYPE_CHECKING
from aioquic.quic.events import QuicEvent, StreamDataReceived, StreamReset, ConnectionTerminated, HandshakeCompleted
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from pathlib import Path
import traceback
import logging

from KeyisBTools import TTLDict
from gnobjects.net.objects import GNRequest, GNResponse, Url
from gnobjects.net.fastcommands import AllGNFastCommands
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

logger = logging.getLogger("GNClient")
logger.setLevel(logging.DEBUG)
logger.propagate = False
if logger.hasHandlers():
    logger.handlers.clear()

formatter = logging.Formatter(
    "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.DEBUG)
console.setFormatter(formatter)
logger.addHandler(console)




async def chain_async(first_item, rest: AsyncIterable) -> AsyncGenerator:
    yield first_item
    async for x in rest:
        yield x

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

        self._rcms_id: Optional[int] = None

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

        if 'data' in self._gn_crt_data:
            data = self._gn_crt_data['data']

            if 'rcms_id' in data:
                self._rcms_id = data['rcms_id']

    
    def setDomain(self, domain: str):
        self._domain = domain

    def setConfiguration(self, configuration: dict):
        self._configuration = configuration

    def addRequestCallback(self, callback: Callable, name: str):
        self.__request_callbacks[name] = callback

    def addResponseCallback(self, callback: Callable, name: str):
        self.__response_callbacks[name] = callback

  
    async def connect(self, request: GNRequest, restart_connection: bool = False, reconnect_wait: float = 10, keep_alive: bool = True) -> 'QuicClient':
        domain = request.url.hostname

        if restart_connection and domain in self._active_connections:
            await self.disconnect(domain)

        if not restart_connection and domain in self._active_connections:
            c = self._active_connections[domain]

            if c.status == 'active' and c._quik_core is not None:
                #logger.debug(f'Reusing active connection to {domain}')
                return c

            if c.status == 'connecting':
                try:
                    await asyncio.wait_for(
                        asyncio.shield(c.connect_future),
                        reconnect_wait or self._configuration.get('L5', {}).get('connection', {}).get('connect_timeout', 10)
                    )
                    if c.status == 'active' and c._quik_core is not None:
                        #logger.debug(f'Reusing active connection to {domain} (post-wait)')
                        return c
                    elif c.status == 'connecting':
                        await self.disconnect(domain)
                        raise AllGNFastCommands.transport.SendTimeout(f'Не удалось отправить запрос (таймаут соединения) с сервером {domain}')
                    elif c.status == 'disconnect':
                        raise AllGNFastCommands.transport.ConnectionError(f'Не удалось подключится к серверу {domain}')
                except asyncio.exceptions.CancelledError:
                    # On Python 3.13 a cancelled shared connect_future may surface here.
                    # Treat as stale connection state and rebuild connection for this domain.
                    await self.disconnect(domain)
                except Exception:
                    await self.disconnect(domain)
            else:
                # stale client instance can remain briefly in map during races
                self._active_connections.pop(domain, None)


        c = QuicClient(self, domain)
        self._active_connections[domain] = c
        data = await self.getDNS(domain, host=domain if request.url.isIp else None)

        data = Url.ipv6_with_port_to_ipv6_and_port(data)
        print(f'Connecting to {domain} dns: {data} (restart_connection={restart_connection}, reconnect_wait={reconnect_wait}, keep_alive={keep_alive})')

        # if data[0].startswith('::ffff:'):
        #     data = (data[0][7:], data[1])

        def f(domain):
            if domain in self._active_connections:
                self._active_connections.pop(domain)

        c._disconnect_signal = f # type: ignore
        try:
            await asyncio.wait_for(c.connect(data[0], data[1], keep_alive=keep_alive), reconnect_wait or self._configuration.get('L5', {}).get('connection', {}).get('connect_timeout', 10))
        except asyncio.exceptions.TimeoutError:
            await self.disconnect(domain)
            raise AllGNFastCommands.transport.QuicHandshakeTimeout(f'Не удалось подключится к серверу {domain} (таймаут рукопожатия)')
        except asyncio.exceptions.CancelledError:
            await self.disconnect(domain)
            raise AllGNFastCommands.transport.ConnectionError(f'Не удалось подключится к серверу {domain}')
        except:
            await self.disconnect(domain)
            raise AllGNFastCommands.transport.ConnectionError(f'Не удалось подключится к серверу {domain}')


        await c.connect_future

        return c

    async def disconnect(self, domain):
        if domain not in self._active_connections:
            return
        
        await self._active_connections[domain].disconnect()


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

    async def request(self, request: GNRequest, keep_alive: bool = True, restart_connection: bool = False, reconnect_wait: float = 10, only_request: bool = False) -> GNResponse:

        logger.debug(f'Request: {request.method} {request.url}')

        if isinstance(request, GNRequest):
            
            request = await self._resolve_requests_transport(request)
            try:
                c = await self.connect(request, restart_connection, reconnect_wait, keep_alive=keep_alive)
            except BaseException as e:
                if isinstance(e, GNResponse):
                    return e
                else:
                    return GNResponse(str(e), payload=traceback.format_exc())


            for f in self.__request_callbacks.values():
                asyncio.create_task(f(request))
            r = await c.asyncRequest(request, only_request=only_request)

            retry_connect_request = (
                isinstance(r, GNResponse)
                and not only_request
                and request.url.path == '/gn/connect'
                and (
                    r.command.transport.ReceiveTimeout
                    or r.command.transport.ConnectionError
                    or r.command.transport.SocketClosed
                )
            )

            if retry_connect_request:
                logger.warning(
                    f"Retrying {request.method} {request.url} after transport failure: {r.command}"
                )
                try:
                    c = await self.connect(
                        request,
                        restart_connection=True,
                        reconnect_wait=reconnect_wait,
                        keep_alive=keep_alive,
                    )
                    r = await c.asyncRequest(request, only_request=only_request)
                except BaseException as e:
                    if isinstance(e, GNResponse):
                        r = e
                    else:
                        r = GNResponse(str(e), payload=traceback.format_exc())

            logger.debug(f'Response: {request.method} {request.url} -> {r.command}')

            for f in self.__response_callbacks.values():
                asyncio.create_task(f(r))

            return r # type: ignore
        
        else:

            c: Optional[QuicClient] = None

            async def wrapped(request) -> AsyncGenerator[GNRequest, None]:
                async for req in request:
                    if req.gn_protocol is None:
                        req.setGNProtocol(self.__current_session['protocols'][0])
                    req._stream = True

                    for f in self.__request_callbacks.values():
                        asyncio.create_task(f(req))

                    nonlocal c
                    if c is None:  # инициализируем при первом req
                        c = await self.connect(request, restart_connection, reconnect_wait, keep_alive=keep_alive)

                    yield req

            gen = wrapped(request)
            first_req = await gen.__anext__()

            if c is None:
                raise AllGNFastCommands.transport.ConnectionError('unknown error')

            r = await c.asyncRequest(chain_async(first_req, gen))

            for f in self.__response_callbacks.values():
                asyncio.create_task(f(r))

            return r



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
            if idle_time > self.quicClient._client._configuration.get('L5', {}).get('disconnection', {}).get('ping_interval', 15):
                self._quic.send_ping(next(self._ping_id_gen))
                self.transmit()
                self._last_activity = time.time()

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
            self._apply_gn_pq_session_root(self._QuicClient.domain)
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
            if self.quicClient is None:
                return

            for state in self._inflight_streams.values():
                message = cast(Union[GNRequest, GNResponse], state['message'])
                message._finishIncomingPayload(False)
            
            self.stop()
            
            asyncio.create_task(self.quicClient.disconnect())



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



    async def request(self, request: GNRequest, only_request: bool = False):
    
        await self._resolve_requests_transport(request)

        sid = self._quic.get_next_available_stream_id()

        fut = asyncio.get_running_loop().create_future()
        if not only_request:
            self._inflight[sid] = fut

        header = request.serializeHeader()
        has_payload = request.payloadSize > 0

        self._quic.send_stream_data(sid, header, end_stream=not has_payload)
        self._schedule_flush()

        if has_payload:
            async for chunk in request.iterSerializedPayload():
                self._quic.send_stream_data(sid, chunk, end_stream=False)
                self._schedule_flush()

            self._quic.send_stream_data(sid, b'', end_stream=True)
            self._schedule_flush()
        elif only_request:
            return AllGNFastCommands.transport.NoResponse()


        if only_request:
            return AllGNFastCommands.transport.NoResponse()
        
        #print(f'Waiting for response on stream {sid}...')
        try:
            data = await asyncio.wait_for(fut, 30)
            #print(f'Response received on stream {sid}, length: {len(data) if data else "None"} bytes')
        except asyncio.exceptions.TimeoutError:
            self._inflight.pop(sid, None)
            self._buffer.pop(sid, None)
            state = self._inflight_streams.pop(sid, None)
            if state is not None:
                cast(Union[GNRequest, GNResponse], state['message'])._finishIncomingPayload(False)
            self._timed_out_streams.add(sid)
            if len(self._timed_out_streams) > 8192:
                self._timed_out_streams.clear()
            print(f'Timeout waiting for response on stream {sid}')
            return AllGNFastCommands.transport.ReceiveTimeout()
        except Exception:
            self._inflight.pop(sid, None)
            self._buffer.pop(sid, None)
            state = self._inflight_streams.pop(sid, None)
            if state is not None:
                cast(Union[GNRequest, GNResponse], state['message'])._finishIncomingPayload(False)
            self._timed_out_streams.add(sid)
            if len(self._timed_out_streams) > 8192:
                self._timed_out_streams.clear()
            print(traceback.format_exc())
            return AllGNFastCommands.transport.ConnectionError()
        #print(f'Raw response data: {data[:100] if data else "None"}{"..." if data and len(data) > 100 else ""}')
        if data is None:
            return AllGNFastCommands.transport.ConnectionError()

        if isinstance(data, GNResponse):
            return data
        
        #print(f'Deserializing response on stream {sid}...')

        r = self._deserialize(data, False)
        return r
    

    async def _serialize(self, d: Union[GNRequest, GNResponse]) -> bytes:
        #TODO

        if isinstance(d, GNRequest):
            return d.serialize()
        return d.serialize()
            

    def _deserialize(self, b: bytes, req: bool) -> Union[GNRequest, GNResponse]:
        #TODO
        
        if req:
            return GNRequest.deserialize(b)
        return GNResponse.deserialize(b)
        
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

    def __init__(self, Client: AsyncClient, domain: str):
        self._client = Client
        self.domain = domain
        self._quik_core: Optional[RawQuicClient] = None
        self._client_cm = None
        self._disconnect_signal = None

        self.status: Literal['active', 'connecting', 'disconnect'] = 'connecting'

        self.connect_future = asyncio.get_event_loop().create_future()
        self.connect_future.add_done_callback(self._consume_future_exception)

        self.ready = asyncio.get_running_loop().create_future()

    async def connect(self, ip: str, port: int, keep_alive: bool = True):
        self.status = 'connecting'
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["gn:backend"])
        cfg.load_verify_locations(cadata=crt_client)
        cfg.idle_timeout = self._client._configuration.get('L5', {}).get('disconnection', {}).get('idle_timeout', 60)

        target_ipv6 = Url.ip_and_port_to_ipv6_with_port(ip, port)
        bootstrap_requires_kdc = self.domain != target_ipv6

        if bootstrap_requires_kdc and self._client.server is not None:
            if not await self._client.server.DEPConfig.isKDCAllowedForDomain(self.domain):
                raise AllGNFastCommands.transport.PolicyDenied({
                    'policy': 'kdc_allowed_domains',
                    'domain': self.domain,
                    'reason': 'KDC bootstrap disabled for domain until GN QUIC handshake key-upgrade is enabled',
                })

        encType = int(bootstrap_requires_kdc)
        if self._client._kdc.getDomainEcryptionType(self.domain) is None:
            self._client._kdc.setDomainEcryptionType(self.domain, encType)
        else:
            encType = self._client._kdc.getDomainEcryptionType(self.domain)

        if encType != 0:
            await self._client._kdc.requestKeyIfNotExist(self.domain)

        try:
            gn_pq_kdc_key = self._client._kdc.getKey(self.domain)
        except Exception:
            gn_pq_kdc_key = None

        gn_pq_client_settings = None
        if bootstrap_requires_kdc:
            gn_pq_client_settings = build_gn_pq_client_settings(
                self.domain,
                kdc_key=gn_pq_kdc_key,
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

            self.status = 'active'


            if not self.ready.done():
                self.ready.set_result(True)

            if keep_alive:
                asyncio.create_task(self._quik_core._keepalive_loop())

            self.status = 'active'
            if not self.connect_future.done():
                self.connect_future.set_result(True)
        except Exception as e:
            print(f'Error connecting: {e}')
            if not self.connect_future.done():
                self.connect_future.set_exception(AllGNFastCommands.transport.ConnectionError('Не удалось подключится к серверу'))
            await self._client_cm.__aexit__(None, None, None)

    async def disconnect(self):
        self.status = 'disconnect'
        
        if self._quik_core is not None:
            self._quik_core.stop()
        

        if self._disconnect_signal is not None:
            self._disconnect_signal(self.domain)
        

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



    async def asyncRequest(self, request: GNRequest, only_request: bool = False):
        if self.status != 'active':
            await self.ready
            if self.status != 'active':
                raise RuntimeError("Connection not active")

        resp = await self._quik_core.request(request, only_request=only_request)

        # After transport-level timeout/errors the current QUIC session can become stale.
        # Drop it so the next request reconnects instead of reusing a broken session.
        if isinstance(resp, GNResponse):
            if resp.command.transport and not resp.command.transport.NoResponse:
                logger.warning(
                    f"Transport session degraded for {self.domain}: {resp.command}. Reconnecting on next request."
                )
                await self.disconnect()

        return resp
