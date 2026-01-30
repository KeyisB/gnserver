


import os
import sys
import asyncio
import inspect
import traceback
import socket
import datetime
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, AsyncGenerator, cast, Coroutine, ParamSpec, Concatenate, TypeVar
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from typing import Any, AsyncGenerator, Union
from aioquic.quic.events import (
    QuicEvent,
    ConnectionTerminated,
    StreamDataReceived,
)
P = ParamSpec("P")
R = TypeVar("R")

from gnobjects.net.objects import GNRequest, GNResponse, FileObject, CORSObject, TempDataGroup, TempDataObject, CacheConfig
from gnobjects.net.fastcommands import AllGNFastCommands, GNFastCommand, AllGNFastCommands as responses

from KeyisBTools.bytes.transformation import userFriendly
from KeyisBTools.models.serialization import deserialize


from ._func_params_validation import register_schema_by_key, validate_params_by_key
from ._cors_resolver import resolve_cors
from ._routes import Route, _compile_path, _ensure_async, _convert_value
from ..client._client import AsyncClient

from ._datagram_enc import QuicProtocolShell, DatagramEndpoint

from ._models import DEPConfig


try:
    if not sys.platform.startswith("win"):
        import uvloop # type: ignore
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    print("uvloop не установлен")




logger = logging.getLogger("GNServer")
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


class App:
    def __init__(self, only_client: bool = False):
        self._only_client = only_client
        self._routes: List[Route] = []
        self._cors: Optional[CORSObject] = None
        self._events: Dict[str, List[Dict[str, Union[Any, Callable]]]] = {}

        self.domain: str = None # type: ignore

        self.DEPConfig = DEPConfig()

        
        self.client = AsyncClient(self)

        
        self._datagramEndpoint: DatagramEndpoint = None # type: ignore

        self.connections: Dict[str, App._ServerProto] = {}

    async def sendObject(self, domain:str, object: Union[TempDataObject, TempDataGroup], end_stream: bool = True):
        a = self.connections.get(domain)
        if a is None:
            return
        await a.sendObject(object, end_stream)

    def route(self, method: str, path: str, cors: Optional[CORSObject] = None, route:str = 'api'):
        if path == '/':
            path = ''
        def decorator(fn: Callable[Concatenate[GNRequest, P], Coroutine[None, None, Union[GNResponse, TempDataObject, TempDataGroup, GNRequest, None]]]):
            regex, param_types = _compile_path(path)
            self._routes.append(
                Route(
                    route,
                    method,
                    path,
                    regex,
                    param_types,
                    _ensure_async(fn),
                    fn.__name__,
                    cors
                )
            )
            register_schema_by_key(fn)
            return fn
        return decorator

    def get(self, path: str, *, cors: Optional[CORSObject] = None):
        return self.route("get", path, cors)

    def post(self, path: str, *, cors: Optional[CORSObject] = None):
        return self.route("post", path, cors)

    def put(self, path: str, *, cors: Optional[CORSObject] = None):
        return self.route("put", path, cors)

    def delete(self, path: str, *, cors: Optional[CORSObject] = None):
        return self.route("delete", path, cors)

    def setRouteCors(self, cors: Optional[CORSObject] = None):
        self._cors = cors
    
    def setDEPConfig(self, config: DEPConfig):
        self.DEPConfig = config
        if self._datagramEndpoint is not None:
            self._datagramEndpoint.DEPConfig = config

    def addEventListener(self, name: str, * , move_to_start: bool = False) -> Callable[[Callable[P, Coroutine[Any, Any, R]]], Callable[P, Coroutine[Any, Any, R]]]:
        def decorator(fn: Callable[P, Coroutine[Any, Any, R]]):
            events = self._events.get(name, [])
            events.append({
                'func': fn,
                'async': inspect.iscoroutinefunction(fn),
                'parameters': inspect.signature(fn).parameters
                })
            if move_to_start:
                events = [events[-1]] + events[:-1]
            self._events[name] = events
            
            return fn
        return decorator

    async def dispatchEvent(self, name: str, *args, **kwargs) -> None:
        handlers = self._events.get(name)
        if not handlers:
            return

        for h in handlers:
            func: Callable = h['func']
            is_async = h['async']
            params = h['parameters']

            if kwargs:
                call_kwargs = {k: v for k, v in kwargs.items() if k in params} # type: ignore
            else:
                call_kwargs = {}

            if is_async:
                await func(*args, **call_kwargs)
            else:
                func(*args, **call_kwargs)

    async def dispatchRequest(
        self, request: GNRequest
    ) -> Union[GNResponse, AsyncGenerator[GNResponse, None]]:
        path    = request.url.path
        method  = request.method
        cand    = {path, path.rstrip("/") or "/", f"{path}/"}
        allowed = set()

        for r in self._routes:
            if r.route != request.route and r.route != '*':
                continue

            if hasattr(request, '_gn_server_proxy_list'):
                if r in request._gn_server_proxy_list: # type: ignore
                    continue
        
            m = next((r.regex.fullmatch(p) for p in cand if r.regex.fullmatch(p)), None)
            if not m:
                continue

            allowed.add(r.method)
            if r.method != method and r.method != '*':
                continue

            resolve_cors(request, r.cors)

            sig = inspect.signature(r.handler)
            def _ann(name: str):
                param = sig.parameters.get(name)
                return param.annotation if param else inspect._empty

            kw: dict[str, Any] = {
                name: _convert_value(val, _ann(name), r.param_types.get(name, str))
                for name, val in m.groupdict().items()
            }

            for qn, qvals in request.url.params.items():
                if qn in kw:
                    continue
                if isinstance(qvals, int):
                    kw[qn] = qvals
                else:
                    raw = qvals if len(qvals) > 1 else qvals[0]
                    kw[qn] = _convert_value(raw, _ann(qn), str)

            
            params = set(sig.parameters.keys())
            kw = {k: v for k, v in kw.items() if k in params}

            
            rv = validate_params_by_key(kw, r.handler)
            if rv is not None:
                raise AllGNFastCommands.UnprocessableEntity({'dev_error': rv, 'user_error': f'Server request error {self.domain}'})

            if "request" in sig.parameters:
                kw["request"] = request

            if inspect.isasyncgenfunction(r.handler):
                return r.handler(**kw)

            result = await r.handler(**kw)

            if result is None:
                continue

            if isinstance(result, GNRequest):
                if not hasattr(request, '_gn_server_proxy_list'):
                    result._gn_server_proxy_list = [r]  # type: ignore
                else:
                    result._gn_server_proxy_list.append(r)  # type: ignore
                return await self.dispatchRequest(result)

            if isinstance(result, (TempDataObject, TempDataGroup)):
                result = responses.ok(result)

            if isinstance(result, GNResponse):
                c = r.cors
                if c is None:
                    if isinstance(result.payload, TempDataObject):
                        if result.payload.cors is not None:
                            c = result.payload.cors
                    elif isinstance(result.payload, TempDataGroup):
                        for tdo in result.payload.payload:
                            if tdo.cors is not None:
                                resolve_cors(request, tdo.cors)

                if c is not None:
                    resolve_cors(request, c)

                return result
            else:
                raise TypeError(
                    f"{r.handler.__name__} returned {type(result)}; GNResponse expected"
                )

        if allowed:
            raise AllGNFastCommands.MethodNotAllowed()
        raise AllGNFastCommands.NotFound()


    def fastFile(self, path: str, file_path: str, cache: Optional[CacheConfig] = None, cors: Optional[CORSObject] = None, inType: Optional[str] = None):
        @self.get(path)  # type: ignore
        async def r_static():
            nonlocal file_path
            if file_path.endswith('/'):
                file_path = file_path[:-1]
                
            if not os.path.isfile(file_path):
                raise AllGNFastCommands.NotFound()

            fileObject = FileObject(file_path)
            return responses.ok(TempDataObject('static', path=path, payload=fileObject, cache=cache, cors=cors, inType=inType))

    def staticDir(self, path: str, dir_path: str, cache: Optional[CacheConfig] = None, cors: Optional[CORSObject] = None, inType: Optional[str] = None):
        @self.get(f"{path}/{{_path:path}}")  # type: ignore
        async def r_static(_path: str):
            file_path = os.path.join(dir_path, _path)
            
            if file_path.endswith('/'):
                file_path = file_path[:-1]
                
            if not os.path.isfile(file_path):
                raise AllGNFastCommands.NotFound()
            
            fileObject = FileObject(file_path)
            return responses.ok(TempDataObject('static', path=f'{path}/{_path}', payload=fileObject, cache=cache, cors=cors, inType=inType))

    def routeObject(self, object: Union[TempDataObject, TempDataGroup]):
        @self.route(object.method, object.path, route='tdo')  # type: ignore
        async def _r_static(request):
            return responses.ok(object)

    def _init_sys_routes(self):
        @self.post('/!gn-vm-host/ping', cors=CORSObject(allow_client_types=['server', 'net']))
        async def r_ping(request: GNRequest):
            if request.client.ip not in ('::1', '127.0.0.1'):
                raise AllGNFastCommands.Forbidden()
            return responses.ok({'time': datetime.datetime.now(datetime.timezone.utc).isoformat()})



    class _ServerProto(QuicProtocolShell):
        def __init__(self, *a, api: "App", datagramEndpoint: DatagramEndpoint, **kw):
            self._api = api

            super().__init__(*a, datagramEndpoint=datagramEndpoint, client=False, **kw)
            self.setDatagramEndpoint(datagramEndpoint)
            self._buffer: Dict[int, bytearray] = {}
            self._streams: Dict[int, Tuple[asyncio.Queue[Optional[GNRequest]], bool]] = {}

            self._domain: str = cast(str, self.datagramEndpoint.getDomain(self))
            self._disconnected = False
            self._init_domain = False

            self._api.connections[self._domain] = self

            asyncio.create_task(self._api.dispatchEvent('connect', proto=self, domain=self._domain))
            
        def quic_event_received(self, event: QuicEvent):
            if isinstance(event, StreamDataReceived):
                buf = self._buffer.setdefault(event.stream_id, bytearray())
                buf.extend(event.data)

                stream_id = event.stream_id

                if event.end_stream:
                    asyncio.create_task(self._resolve_raw_request(stream_id, buf))
            

            elif isinstance(event, ConnectionTerminated):
                reason = event.reason_phrase or f"code={event.error_code}"
                self._trigger_disconnect(f"ConnectionTerminated: {reason}")
            
            
        def connection_lost(self, exc):
            self._trigger_disconnect(f"Transport closed: {exc!r}")

        def _trigger_disconnect(self, reason: str):
            if self._disconnected:
                return
            self._disconnected = True

            logger.info(f"[DISCONNECT]  — {reason}")

            
            asyncio.create_task(self._api.dispatchEvent('disconnect', domain=self._domain, L5_reason=reason))

        async def _resolve_raw_request(self, stream_id: int, data: bytes):
    
            request = GNRequest.deserialize(data)
                
            await self._resolve_dev_transport_request(request)

            
            if self._domain is None:
                asyncio.create_task(self.sendRawResponse(stream_id, GNResponse('error', {'error': 'domain not set'})))
                return
            
            request.client._data['domain'] = self._domain
            
            request.client._data['remote_addr'] = self._quic._network_paths[0].addr
            request.stream_id = stream_id   # type: ignore

            request._assembly_server()

            self._buffer.pop(stream_id, None)
            await self._handle_request(request)

        async def _resolve_dev_transport_request(self, request: GNRequest):
            if not request.transportObject.routeProtocol.dev:
                return
            
            if request.cookies is not None:
                data: Optional[dict] = request.cookies.get('gn', {}).get('request', {}).get('transport', {}).get('::dev')
                if data is not None:
                    if 'netstat' in data:
                        if 'way' in data['netstat']:
                            data['netstat']['way']['data'].append({
                                'object': f'{self._domain}',
                                'step': '4',
                                'type': 'L6',
                                'action': 'rosolve',
                                'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                'route': str(request.route),
                                'method': request.method,
                                'url': str(request.url),
                            })

        async def _resolve_dev_transport_response(self, response: GNResponse, request: GNRequest):
            
            if request.cookies is None:
                return
            
            gn_ = request.cookies.get('gn')
            if gn_ is not None:
                if response._cookies is None:
                    response._cookies = {}
                response._cookies['gn'] = gn_

            if not request.transportObject.routeProtocol.dev:
                return

            data: Optional[dict] = response.cookies.get('gn', {}).get('request', {}).get('transport', {}).get('::dev')
            if data is None:
                return
            
            if 'netstat' in data:
                if 'way' in data['netstat']:
                    data['netstat']['way']['data'].append({
                        'object': f'{self._domain}',
                        'type': 'L6',
                        'action': 'rosolve',
                        'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'route': str(request.route),
                        'method': request.method,
                        'url': str(request.url)
                    })


        async def _handle_request(self, request: GNRequest):

            try:
                response = await self._api.dispatchRequest(request)

                if inspect.isasyncgen(response):
                    async for chunk in response:  # type: ignore
                        chunk._stream = True
                        await self._sendResponseFromRequest(request, chunk, False)
                        
                    resp = GNResponse('gn:end-stream')
                    resp._stream = True # type: ignore

                    await self._sendResponseFromRequest(request, resp)
                    return

                if not isinstance(response, GNResponse):
                    await self._sendResponseFromRequest(request, AllGNFastCommands.InternalServerError('Invalid response'))
                    return

                await self._sendResponseFromRequest(request, response)
            except Exception as e:
                if isinstance(e, (GNRequest, GNFastCommand)):
                    await self._sendResponseFromRequest(request, e)
                else:
                    logger.error('InternalServerError:\n'  + traceback.format_exc())

                    await self._sendResponseFromRequest(request, AllGNFastCommands.InternalServerError())
            

        
        async def _sendResponseFromRequest(self, request: GNRequest, response: GNResponse, end_stream: bool = True):
            await self._resolve_dev_transport_response(response, request)

            logger.debug(f'[>] [{request.client.domain}] Response: {request.method} {request.url} -> {response.command} {response.payload if len(str(response.payload)) < 256 else ''}')
            
            await self.sendRawResponse(request.stream_id, response=response, end_stream=end_stream)  # type: ignore

        async def sendRawResponse(self, stream_id: int, response: GNResponse, end_stream: bool = True):
            await response.assembly()
            blob = response.serialize()
            self._quic.send_stream_data(stream_id, blob, end_stream=end_stream) # type: ignore
            self.transmit()
        
        async def sendObject(self, object: Union[TempDataObject, TempDataGroup], end_stream: bool = True):
            if isinstance(object, TempDataGroup):
                await object.assemble()
                blob = object.serialize()
            else:
                object.assemble()
                blob = await object.serialize()
            
            sid = self._quic.get_next_available_stream_id()
            self._quic.send_stream_data(sid, blob, end_stream=end_stream)

    def run(
        self,
        domain: str,
        port: int,
        tls_certfile: Union[bytes, str],
        tls_keyfile: Union[bytes, str],
        *,
        host: Union[str, Tuple[str, str]] = '::',
        idle_timeout: float = 20.0,
        wait: bool = True,
        run: Optional[Callable] = None
    ):
        """
        # Запустить сервер

        Запускает сервер в главном процессе asyncio.run()
        """

        self.domain = domain


        self.client.setDomain(domain)




        self._init_sys_routes()

        cfg = QuicConfiguration(
            alpn_protocols=["gn:backend"], is_client=False, idle_timeout=idle_timeout
        )


        
        from aioquic.tls import (
            load_pem_private_key,
            load_pem_x509_certificates,
        )
        from re import split


        if os.path.isfile(tls_certfile):
            with open(tls_certfile, "rb") as fp:
                boundary = b"-----BEGIN PRIVATE KEY-----\n"
                chunks = split(b"\n" + boundary, fp.read())
                certificates = load_pem_x509_certificates(chunks[0])
                if len(chunks) == 2:
                    private_key = boundary + chunks[1]
                    cfg.private_key = load_pem_private_key(private_key)
            cfg.certificate = certificates[0]
            cfg.certificate_chain = certificates[1:]
        else:
            if isinstance(tls_certfile, str):
                tls_certfile = tls_certfile.encode()
                
            boundary = b"-----BEGIN PRIVATE KEY-----\n"
            chunks = split(b"\n" + boundary, tls_certfile)
            certificates = load_pem_x509_certificates(chunks[0])
            if len(chunks) == 2:
                private_key = boundary + chunks[1]
                cfg.private_key = load_pem_private_key(private_key)
            cfg.certificate = certificates[0]
            cfg.certificate_chain = certificates[1:]

        
        if os.path.isfile(tls_keyfile):
            
            with open(tls_keyfile, "rb") as fp:
                cfg.private_key = load_pem_private_key(
                    fp.read()
                )
        else:
            if isinstance(tls_keyfile, str):
                tls_keyfile = tls_keyfile.encode()
            cfg.private_key = load_pem_private_key(
                tls_keyfile
            )

        if cfg.certificate is None or cfg.private_key is None:
            raise Exception('Не удалось загрузить TLS сертификат или ключ')

        async def _main():
            
            await self.dispatchEvent('start')
            if not self._only_client:
                self._datagramEndpoint: DatagramEndpoint = None # type: ignore

                def proto_factory(*a, **kw):
                    return App._ServerProto(*a, api=self, datagramEndpoint=self._datagramEndpoint, **kw)

                quic_server = QuicServer(
                    configuration=cfg,
                    create_protocol=proto_factory,
                )

                self._datagramEndpoint = DatagramEndpoint(quic_server, self.client._kdc, dEPConfig=self.DEPConfig)

                loop = asyncio.get_event_loop()


                nonlocal host
                if host == '0.0.0.0':
                    host = ('::', '0.0.0.0')
            

                if isinstance(host, str):
                    if ',' in host:
                        host = cast(Tuple[str, str], tuple([x.strip() for x in host.split(',')]))
                    host = (host,) # type: ignore



                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                sock.bind((host[0], int(port), 0, 0))



                await loop.create_datagram_endpoint(
                    lambda: self._datagramEndpoint,
                    sock=sock
                )

                # if len(host) == 2: # 1 or 2
                #     print(f'binding [{(host[1], int(port))}]')
                #     sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                #     sock4.bind((host[1], int(port)))

                #     await loop.create_datagram_endpoint(
                #         lambda: datagramEndpoint,
                #         sock=sock4
                #     )


                # async def f():
                #     print('checking...')
                #     print(f'datagram_endpoint transport {a.is_closing()}')
                #     await asyncio.sleep(0.5)
                #     await f()

                # loop.create_task(f())

            if run is not None:
                await run()
            

            logger.debug('Server startup completed')
            if wait:
                await asyncio.Event().wait()

        asyncio.run(_main())


    def runByVMHost(self): 
        """
        # Запусить через VM-host

        Заупскает сервер через процесс vm-host
        """
        argv = sys.argv[1:]
        data_enc = argv[0]

        data: dict = deserialize(userFriendly.decode(data_enc)) # type: ignore

        if data['command'] == 'gn:vm-host:start':
            self.run(
                domain=data['domain'],
                port=data['port'],
                tls_certfile=data.get('cert_path'), # type: ignore
                tls_keyfile=data.get('key_path'), # type: ignore
                host=data.get('host', '0.0.0.0')
            )