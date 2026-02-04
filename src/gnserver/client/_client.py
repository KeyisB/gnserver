import os
import sys
import time
import asyncio
import datetime
from itertools import count
from collections import deque
from typing import Any, Dict, Deque, Tuple, Union, Optional, AsyncGenerator, Callable, Literal, AsyncIterable, cast, overload, Coroutine, List, TYPE_CHECKING
from aioquic.quic.events import QuicEvent, StreamDataReceived, StreamReset, ConnectionTerminated
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from pathlib import Path
import traceback
import logging

from KeyisBTools import TTLDict
from gnobjects.net.objects import GNRequest, GNResponse, Url, unpack_payload
from gnobjects.net.fastcommands import AllGNFastCommands
from gnobjects.net.domains import GNDomain

from .._crt import crt_client, ml_kem_crt_client
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
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
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


class AsyncClient:
    def __init__(self, server: Optional['App'] = None):
        self.server = server
        self.__dns_core__ipv4 = Url.ipv4_with_port_to_ipv6_with_port('85.198.86.175:55713')
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
        

    def init(self,
             gn_crt: Union[bytes, str, Path],
             requested_domains: List[str] = [],
             active_key_synchronization: bool = True,
             active_key_synchronization_callback: Optional[Callable[[List[Union[str, int]]], Union[List[Tuple[int, str, bytes]], Coroutine]]] = None,
             active_key_synchronization_callback_domainFilter: Optional[List[str]] = None
             ):

        if gn_crt is None:
            return

        from ..server._gnserver import GNServer as _gnserver

        self._gn_crt_data = _gnserver._get_gn_server_crt(gn_crt, self._domain)

        self._kdc.init(
            self._gn_crt_data,
            requested_domains,
            active_key_synchronization,
            active_key_synchronization_callback,
            active_key_synchronization_callback_domainFilter
        )

    
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
        if not restart_connection and domain in self._active_connections:
            c = self._active_connections[domain]
            if c.status == 'connecting':
                try:
                    await asyncio.wait_for(c.connect_future, reconnect_wait or self._configuration.get('L5', {}).get('connection', {}).get())
                    if c.status == 'active':
                        return c
                    elif c.status == 'connecting':
                        await self.disconnect(domain)
                        raise AllGNFastCommands.transport.SendTimeout()
                    elif c.status == 'disconnect':
                        raise AllGNFastCommands.transport.ConnectionError()
                except:
                    await self.disconnect(domain)
            else:
                return c

        c = QuicClient(self, domain)
        self._active_connections[domain] = c
        data = await self.getDNS(domain, raise_errors=True, host=domain if request.url.isIp else None)

        data = Url.ipv6_with_port_to_ipv6_and_port(data)



        def f(domain):
            if domain in self._active_connections:
                self._active_connections.pop(domain)

        c._disconnect_signal = f # type: ignore
        try:
            await c.connect(data[0], data[1], keep_alive=keep_alive)
        except asyncio.exceptions.CancelledError:
            raise AllGNFastCommands.transport.ConnectionError('Не удалось подключится к серверу')
        except:
            raise AllGNFastCommands.transport.ConnectionError()


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

        print(f'Request: {request.method} {request.url}')

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
            logger.debug(f'Response: {request.method} {request.url} -> {r.command} {r.payload if len(str(r.payload)) < 512 else f'len({len(str(r.payload))})'}')

            for f in self.__response_callbacks.values():
                asyncio.create_task(f(r))

            return r
        
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
                raise Exception('unknown error')

            r = await c.asyncRequest(chain_async(first_req, gen))

            for f in self.__response_callbacks.values():
                asyncio.create_task(f(r))

            return r




    @overload
    async def getDNS(self, domain: str, use_cache: bool = True, keep_alive: bool = False, raise_errors: Literal[False] = False, host: Optional[str] = None) -> GNResponse: ...
    @overload
    async def getDNS(self, domain: str, use_cache: bool = True, keep_alive: bool = False, raise_errors: Literal[True] = True, host: Optional[str] = None) -> str: ...

    async def getDNS(self, domain: str, use_cache: bool = True, keep_alive: bool = False, raise_errors: bool = False, host: Optional[str] = None) -> Union[str, GNResponse]:
        if use_cache:
            resuilt = self._dns_cache.get(domain)
            if resuilt is not None:
                if raise_errors:
                    r1_data = resuilt.payload
                    result = Url.ip_and_port_to_ipv6_with_port(r1_data['ip'], r1_data['port'])
                else:
                    result = resuilt
                return result
            
        if host is not None:
            return Url.ipv4_with_port_to_ipv6_with_port(host)
            

        if ':' in domain and domain.split('.')[-1].split(':')[0].isdigit() and domain.split(':')[-1].isdigit():
            return Url.ipv4_with_port_to_ipv6_with_port(domain)
        
        if domain == 'api.dns.core':
            return self.__dns_core__ipv4
        elif domain == 'api.dns.gn':
            if self.__dns_gn__ipv4 is None:
                a = await self.getDNS('!api.dns.gn', raise_errors=raise_errors)
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
                a = await self.getDNS('api.dns.gn', raise_errors=raise_errors)
                if not isinstance(a, str):
                    return a
                else:
                    self.__dns_gn__ipv4 = a


        if is_dns_core:
            domain_dns = 'api.dns.core'
            if domain == 'kdc.core':
                domain_dns = self.__dns_core__ipv4
        else:
            domain_dns = 'api.dns.gn'

        r1 = await self.request(GNRequest('get', Url(f'gn://{domain_dns}/getIp?d={domain}'), payload=domain), keep_alive=keep_alive)

        if not r1.command.ok:
            if raise_errors:
                raise r1
            else:
                return r1

        self._dns_cache.set(domain, r1, r1.payload.get('ttl', 60)) # type: ignore

        if raise_errors:
            r1_data = r1.payload
            result = Url.ip_and_port_to_ipv6_with_port(r1_data['ip'], r1_data['port']) # type: ignore
        else:
            result = r1
        return result

    # def upgradeConnection(self, domain: str, alg: str): pass



class RawQuicClient(QuicProtocolShell):

    def __init__(self, quic: QuicConnection, datagramEndpoint, client: 'QuicClient', stream_handler):
        self._client = client
        
        super().__init__(quic, datagramEndpoint=datagramEndpoint, client=True, stream_handler=stream_handler)

        self.quicClient: QuicClient = None # type: ignore

        self._queue_sys: Deque[Tuple[int, bytes, bool]] = deque()
        self._queue_user: Deque[Tuple[int, bytes, bool]] = deque()

        self._inflight: Dict[int, Union[asyncio.Future, asyncio.Queue[Optional[GNResponse]]]] = {}
        self._inflight_streams: Dict[int, bytearray] = {}
        self._buffer: Dict[Union[int, str], bytearray] = {}

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

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            handler = self._inflight.get(event.stream_id)
            if handler is None:
                if self._client._client.server is None:
                    return
                buf = self._buffer.setdefault(event.stream_id, bytearray())
                buf.extend(event.data)
                if not event.end_stream:
                    return
                self._inflight.pop(event.stream_id, None)
                data = bytes(self._buffer.pop(event.stream_id, b""))

                u = unpack_payload(data)
                if not isinstance(u, GNRequest):
                    u = GNRequest('get', Url('gn://[::1]/'), payload=u, route=':receive') # type: ignore
                self._loop.create_task(self._client._client.server.dispatchRequest(u))
            else:
                if not isinstance(handler, asyncio.Queue):
                    buf = self._buffer.setdefault(event.stream_id, bytearray())
                    buf.extend(event.data)
                    if not event.end_stream:
                        return
                    self._inflight.pop(event.stream_id, None)
                    data = bytes(self._buffer.pop(event.stream_id, b""))
                    if not handler.done():
                        handler.set_result(data)
                else:
                    raise NotImplementedError
                

        # ─── RESET ──────────────────────────────────────────
        elif isinstance(event, StreamReset):
            handler = self._inflight.pop(event.stream_id, None)
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
        blob = await self._serialize(request)

        sid = self._quic.get_next_available_stream_id()

        fut = asyncio.get_running_loop().create_future()
        if not only_request:
            self._inflight[sid] = fut
        
        self._quic.send_stream_data(sid, blob, end_stream=True)
        self._schedule_flush()


        if only_request:
            return AllGNFastCommands.transport.NoResponse()

        try:
            data = await fut
        except:
            return AllGNFastCommands.transport.ConnectionError()
        
        if data is None:
            return AllGNFastCommands.transport.ConnectionError()

        r = self._deserialize(data, False)
        return r
    

    async def _serialize(self, d: Union[GNRequest, GNResponse]) -> bytes:
        #TODO
        
        
        if isinstance(d, GNRequest):
            return await d.serialize()
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

    def __init__(self, Client: AsyncClient, domain: str):
        self._client = Client
        self.domain = domain
        self._quik_core: Optional[RawQuicClient] = None
        self._client_cm = None
        self._disconnect_signal = None

        self.status: Literal['active', 'connecting', 'disconnect'] = 'connecting'

        self.connect_future = asyncio.get_event_loop().create_future()

    async def connect(self, ip: str, port: int, keep_alive: bool = True):
        self.status = 'connecting'
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["gn:backend"])
        cfg.load_verify_locations(cadata=crt_client)
        cfg.idle_timeout = self._client._configuration.get('L5', {}).get('disconnection', {}).get('idle_timeout', 60)

        encType = int(not self.domain == Url.ip_and_port_to_ipv6_with_port(ip, port))
        if self._client._kdc.getDomainEcryptionType(self.domain) is None:
            self._client._kdc.setDomainEcryptionType(self.domain, encType)
        else:
            encType = self._client._kdc.getDomainEcryptionType(self.domain)

        if encType != 0:
            await self._client._kdc.requestKeyIfNotExist(self.domain)

        self._client_cm = connect(
            self,
            ip,
            port,
            self.domain,
            configuration=cfg,
            create_protocol=RawQuicClient,
            wait_connected=True,
            encType=encType  # type: ignore
        )

        try:
            self._quik_core = await self._client_cm.__aenter__() # type: ignore
            self._quik_core.quicClient = self

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
                    fut.set_exception(Exception)



            self._quik_core.close()
            await self._quik_core.wait_closed()
            self._quik_core = None

            if self._client_cm is not None:
                await self._client_cm.__aexit__(None, None, None)
                self._client_cm = None

    async def asyncRequest(self, request: GNRequest, only_request: bool = False) -> GNResponse:
        if self._quik_core is None:
            raise RuntimeError("Not connected")
        
        resp = await self._quik_core.request(request, only_request=only_request)
        return resp  # type: ignore

