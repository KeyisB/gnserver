
from __future__ import annotations
import os
import sys
import asyncio
import inspect
import traceback
import socket
import datetime
import logging
from typing import Any, Awaitable, Callable, Concatenate, Dict, List, Optional, Tuple, Union, AsyncGenerator, cast, Coroutine, ParamSpec, Protocol, TypeAlias, TypeVar, Literal, overload
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicErrorCode
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.events import (
    QuicEvent,
    ConnectionTerminated,
    HandshakeCompleted,
    StreamDataReceived,
    StreamReset,
)
from pathlib import Path
P = ParamSpec("P")
R = TypeVar("R")

from gnobjects.net.objects import GNRequest, GNResponse, FileObject, TempDataGroup, TempDataObject, Url, DMPContainer, STPContainer
from gnobjects.net.fastcommands import AllGNFastCommands, GNFastCommand, AllGNFastCommands as responses
from gnobjects.net.base_model import DataModel, DataModelError, DataModelValidationError, model_validate
from pydantic import BaseModel as PydanticBaseModel, ValidationError


from KeyisBTools.bytes.transformation import userFriendly
from KeyisBTools.models.serialization import deserialize


from ._func_params_validation import register_schema_by_key, validate_params_by_key
from ._cors_resolver import resolve_cors
from ._routes import Route, _compile_path, _ensure_async, _convert_value
from ..client._client import AsyncClient
from .._gn_pq_quic import GNQuicServer

from ._datagram_enc import QuicProtocolShell, DatagramEndpoint

from ._models import DEPConfig, CORSObject


_RouteReturn: TypeAlias = Union[GNResponse, TempDataObject, TempDataGroup, GNRequest, None]
_DataModelT = TypeVar("_DataModelT", bound=DataModel)
_PydanticModelT = TypeVar("_PydanticModelT", bound=PydanticBaseModel)

_RequestRouteHandler: TypeAlias = Callable[Concatenate[GNRequest, P], Awaitable[_RouteReturn]]
_DataModelRouteHandler: TypeAlias = Callable[Concatenate[_DataModelT, P], Awaitable[_RouteReturn]]
_PydanticRouteHandler: TypeAlias = Callable[Concatenate[_PydanticModelT, P], Awaitable[_RouteReturn]]
_RequestDataModelRouteHandler: TypeAlias = Callable[Concatenate[GNRequest, _DataModelT, P], Awaitable[_RouteReturn]]
_DataModelRequestRouteHandler: TypeAlias = Callable[Concatenate[_DataModelT, GNRequest, P], Awaitable[_RouteReturn]]
_RequestPydanticRouteHandler: TypeAlias = Callable[Concatenate[GNRequest, _PydanticModelT, P], Awaitable[_RouteReturn]]
_PydanticRequestRouteHandler: TypeAlias = Callable[Concatenate[_PydanticModelT, GNRequest, P], Awaitable[_RouteReturn]]


class _RouteDecorator(Protocol):
    @overload
    def __call__(self, fn: _RequestRouteHandler[P]) -> _RequestRouteHandler[P]: ...

    @overload
    def __call__(self, fn: _DataModelRouteHandler[_DataModelT, P]) -> _DataModelRouteHandler[_DataModelT, P]: ...

    @overload
    def __call__(self, fn: _PydanticRouteHandler[_PydanticModelT, P]) -> _PydanticRouteHandler[_PydanticModelT, P]: ...

    @overload
    def __call__(
        self,
        fn: _RequestDataModelRouteHandler[_DataModelT, P]
    ) -> _RequestDataModelRouteHandler[_DataModelT, P]: ...

    @overload
    def __call__(
        self,
        fn: _DataModelRequestRouteHandler[_DataModelT, P]
    ) -> _DataModelRequestRouteHandler[_DataModelT, P]: ...

    @overload
    def __call__(
        self,
        fn: _RequestPydanticRouteHandler[_PydanticModelT, P]
    ) -> _RequestPydanticRouteHandler[_PydanticModelT, P]: ...

    @overload
    def __call__(
        self,
        fn: _PydanticRequestRouteHandler[_PydanticModelT, P]
    ) -> _PydanticRequestRouteHandler[_PydanticModelT, P]: ...




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

_Name = Union[Literal['start'], str]

def _path_to_iter_tdo(path: str, chunk_size: int) -> AsyncGenerator[bytes, None]:
    if not os.path.isfile(path):
        raise AllGNFastCommands.NotFound({'code': 3, 'message': f'File not found: {path}'})

    return FileObject(path).toIterTempDataObject(chunk_size=chunk_size)


class App:
    def __init__(self, only_client: bool = False):
        self._only_client = only_client
        self._routes: List[Route] = []
        self._cors: Optional[CORSObject] = CORSObject()
        self._events: Dict[str, List[Dict[str, Union[Any, Callable]]]] = {}

        # Route indexes for hot path dispatch.
        self._route_order_seq: int = 0
        self._route_order: Dict[int, int] = {}
        self._route_is_static: Dict[int, bool] = {}
        self._route_static_index: Dict[str, Dict[str, List[Route]]] = {}
        self._route_dynamic_prefix_index: Dict[str, Dict[str, List[Route]]] = {}
        self._route_dynamic_fallback_index: Dict[str, List[Route]] = {}

        # Per-route cached handler metadata.
        self._route_param_names: Dict[int, set[str]] = {}
        self._route_annotations: Dict[int, Dict[str, Any]] = {}
        self._route_is_asyncgen: Dict[int, bool] = {}
        self._route_schema: dict[int, Any] = {}

        self.domain: str = None # type: ignore

        self.DEPConfig = DEPConfig()

        
        self.client = AsyncClient(self)

        
        self._datagramEndpoint: DatagramEndpoint = None # type: ignore

        self.connections: Dict[str, App._ServerProto] = {}


        self._togn_requests_inflight: dict[int, asyncio.Future] = {}
        self._togn_requests_inflight_c: int = 0


    @staticmethod
    def _is_static_route_path(path_expr: str) -> bool:
        return path_expr != '*' and not path_expr.startswith('!') and '{' not in path_expr

    @staticmethod
    def _extract_first_literal_segment(path_expr: str) -> Optional[str]:
        if path_expr == '*' or path_expr.startswith('!'):
            return None
        if not path_expr.startswith('/'):
            return None

        rest = path_expr.lstrip('/')
        if not rest:
            return None

        seg = rest.split('/', 1)[0]
        if not seg or '{' in seg:
            return None
        return seg

    @staticmethod
    def _build_path_candidates(path: str) -> Tuple[str, ...]:
        p = path or '/'
        if p == '/':
            return ('/',)

        alt = p.rstrip('/') or '/'

        if p == alt:
            extra = f'{p}/'
            return (p, extra)

        return (p, alt)

    @staticmethod
    def _path_first_segment(path: str) -> Optional[str]:
        p = path.strip('/')
        if not p:
            return None
        return p.split('/', 1)[0]

    def _route_scopes(self, request_route: Optional[str]) -> Tuple[Optional[str], ...]:
        if request_route == '*':
            return ('*',)
        return (request_route, '*')

    @staticmethod
    def _match_route_path(route: Route, path_candidates: Tuple[str, ...]):
        for candidate in path_candidates:
            m = route.regex.fullmatch(candidate)
            if m is not None:
                return m
        return None

    def _index_route(self, route: Route) -> None:
        rid = id(route)
        self._route_order[rid] = self._route_order_seq
        self._route_order_seq += 1

        sig = inspect.signature(route.handler)
        self._route_param_names[rid] = set(sig.parameters.keys())
        self._route_annotations[rid] = {name: p.annotation for name, p in sig.parameters.items()}
        self._route_is_asyncgen[rid] = inspect.isasyncgenfunction(route.handler)
        self._route_schema[rid] = register_schema_by_key(route.handler)

        is_static = self._is_static_route_path(route.path_expr)
        self._route_is_static[rid] = is_static

        route_bucket = route.route

        if is_static:
            static_map = self._route_static_index.setdefault(route_bucket, {})
            static_map.setdefault(route.path_expr, []).append(route)
            return

        seg = self._extract_first_literal_segment(route.path_expr)
        if seg is None:
            self._route_dynamic_fallback_index.setdefault(route_bucket, []).append(route)
            return

        prefix_map = self._route_dynamic_prefix_index.setdefault(route_bucket, {})
        prefix_map.setdefault(seg, []).append(route)

    def _collect_candidate_routes(self, request_route: Optional[str], path_candidates: Tuple[str, ...]) -> List[Route]:
        by_id: Dict[int, Route] = {}

        first_segments = {
            seg
            for seg in (self._path_first_segment(p) for p in path_candidates)
            if seg is not None
        }

        for scope in self._route_scopes(request_route):
            static_map = self._route_static_index.get(cast(str, scope), {})
            for p in path_candidates:
                for r in static_map.get(p, ()):  # exact path bucket
                    by_id.setdefault(id(r), r)

            dynamic_prefix_map = self._route_dynamic_prefix_index.get(cast(str, scope), {})
            for seg in first_segments:
                for r in dynamic_prefix_map.get(seg, ()):  # literal first-segment bucket
                    by_id.setdefault(id(r), r)

            for r in self._route_dynamic_fallback_index.get(cast(str, scope), ()):  # regex/wildcard bucket
                by_id.setdefault(id(r), r)

        return sorted(by_id.values(), key=lambda r: self._route_order.get(id(r), 0))

    async def sendRequest(self, request: GNRequest, end_stream: bool = True) -> bool:
        """
        # Запрос периспользующий входящее соединение

        Возвращает `True`, если запрос отправлен по существующему входящему
        соединению, и `False`, если соединения к `request.url.hostname` нет.
        """
        a = self.connections.get(request.url.hostname)
        if a is None:
            return False
        await a.sendRequest(request, end_stream)
        return True

    async def requestToGN(self, request: GNRequest) -> GNResponse:
        """
        # Запрос к системе GN

        Проталкивает `request` в сеть GN через активное входящее соединение от слоя
        origin shield (`*~api.origin.shield.gn`).

        Запрос отправляется обратным запросом по входящему каналу shield: header
        исходного запроса передаётся в cookie, а его payload отправляется чанками
        (`iterSerializedPayload`). Ответ приходит отдельным запросом на роут
        `/response` (`gn:shield-origin:response`) и резолвит future по `id`.
        """
        self._togn_requests_inflight_c += 1
        _id = self._togn_requests_inflight_c

        chunk_size = self.DEPConfig.iter_payload_chunk_size

        rq = GNRequest(
            'post',
            Url('gn://*~api.origin.shield.gn/r'),
            payload=request.iterSerializedPayload(chunk_size),
            cookies={
                'header': request.serializeHeader(),
                'id': _id,
            }
        )

        loop = asyncio.get_running_loop()
        f = loop.create_future()
        self._togn_requests_inflight[_id] = f

        send_task = asyncio.create_task(self.sendRequest(rq))
        send_task_done = False
        try:
            response_header_deadline = loop.time() + 15.0
            data_ready = False
            resp: GNResponse | None = None

            while not data_ready:
                timeout = max(0.0, response_header_deadline - loop.time())
                if timeout <= 0.0:
                    if not send_task.done():
                        send_task.cancel()
                    return AllGNFastCommands.transport.ReceiveTimeout()

                wait_items: set[asyncio.Future | asyncio.Task] = {f}
                if not send_task_done:
                    wait_items.add(send_task)

                done, _ = await asyncio.wait(wait_items, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    if not send_task.done():
                        send_task.cancel()
                    return AllGNFastCommands.transport.ReceiveTimeout()

                if send_task in done:
                    send_task_done = True
                    if not await send_task:
                        return AllGNFastCommands.transport.NetworkUnreachable()

                if f in done:
                    resp = cast(GNResponse, f.result())
                    data_ready = True

            if not send_task_done:
                def _consume_send_task_exception(task: asyncio.Task[bool]) -> None:
                    if task.cancelled():
                        return
                    try:
                        task.result()
                    except Exception:
                        logger.error(f'requestToGN body send failed after response header for id {_id}:\n{traceback.format_exc()}')

                send_task.add_done_callback(_consume_send_task_exception)
                resp._request_send_task = send_task
        except asyncio.TimeoutError:
            if not send_task.done():
                send_task.cancel()
            return AllGNFastCommands.transport.ReceiveTimeout()
        except asyncio.CancelledError:
            if not send_task.done():
                send_task.cancel()
            raise
        except Exception as e:
            logger.error(f'requestToGN: ошибка ожидания ответа: {e}')
            if not send_task.done():
                send_task.cancel()
            return AllGNFastCommands.transport.ConnectionError()
        finally:
            self._togn_requests_inflight.pop(_id, None)
        return resp



        

    def route(
        self,
        method: str,
        path: str,
        cors: Optional[CORSObject] = None,
        route: str = 'api',
    ) -> _RouteDecorator:
        if path == '':
            path = '/'

        def decorator(fn: Callable[..., Awaitable[_RouteReturn]]) -> Callable[..., Awaitable[_RouteReturn]]:
            regex, param_types = _compile_path(path)
            route_obj = Route(
                route,
                method,
                path,
                regex,
                param_types,
                _ensure_async(fn),
                fn.__name__,
                cors
            )
            self._routes.append(route_obj)
            self._index_route(route_obj)
            register_schema_by_key(fn)
            return fn
        return cast(_RouteDecorator, decorator)

    def get(self, path: str, *, cors: Optional[CORSObject] = None) -> _RouteDecorator:
        return self.route("get", path, cors)

    def post(self, path: str, *, cors: Optional[CORSObject] = None) -> _RouteDecorator:
        return self.route("post", path, cors)

    def put(self, path: str, *, cors: Optional[CORSObject] = None) -> _RouteDecorator:
        return self.route("put", path, cors)

    def delete(self, path: str, *, cors: Optional[CORSObject] = None) -> _RouteDecorator:
        return self.route("delete", path, cors)

    def setRouteCors(self, cors: Optional[CORSObject] = None):
        self._cors = cors
    
    def setDEPConfig(self, config: DEPConfig):
        self.DEPConfig = config
        if self._datagramEndpoint is not None:
            self._datagramEndpoint.DEPConfig = config

    @staticmethod
    def _loadInterval(score_0_10000: int) -> str:
        if score_0_10000 < 3000:
            return 'low'
        if score_0_10000 < 6000:
            return 'medium'
        if score_0_10000 < 8500:
            return 'high'
        return 'critical'

    def getCurrentLoadMetrics(self) -> dict:
        if self._datagramEndpoint is None:
            return {
                'score': 0,
                'load_percent': 0.0,
                'interval': self._loadInterval(0),
                'window_seconds': 5.0,
                'queue_fill_ratio': 0.0,
                'drop_rate_10s': 0.0,
                'p95_udp_queue_wait_ms': 0.0,
            }

        metrics = self._datagramEndpoint.getInboundLoadMetrics()

        queue_fill_ratio = max(0.0, min(1.0, float(metrics.get('queue_fill_ratio', 0.0))))
        drop_rate_10s = max(0.0, min(1.0, float(metrics.get('drop_rate_10s', 0.0))))
        p95_udp_queue_wait_ms = max(0.0, float(metrics.get('p95_udp_queue_wait_ms', 0.0)))

        # p95 queue wait normalization: >=250ms is considered fully saturated.
        p95_wait_norm = min(1.0, p95_udp_queue_wait_ms / 250.0)

        weighted = (
            queue_fill_ratio * 0.40
            + drop_rate_10s * 0.30
            + p95_wait_norm * 0.20
        )

        # Normalize to full [0..1] range because the configured weights sum to 0.90.
        normalized = min(1.0, weighted / 0.90)

        score = int(round(normalized * 10000.0))
        if score < 0:
            score = 0
        if score > 10000:
            score = 10000
        
        return {
            'score': score,
            'load_percent': score / 100.0,
            'interval': self._loadInterval(score),
            'window_seconds': float(metrics.get('window_seconds', 5.0)),
            'queue_fill_ratio': float(metrics.get('queue_fill_ratio', 0.0)),
            'drop_rate_10s': float(metrics.get('drop_rate_10s', 0.0)),
            'p95_udp_queue_wait_ms': float(metrics.get('p95_udp_queue_wait_ms', 0.0)),
        }


    def addEventListener(self, name: _Name | str, * , move_to_start: bool = False) -> Callable[[Callable[P, Coroutine[Any, Any, R]]], Callable[P, Coroutine[Any, Any, R]]]:
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
        self, request: GNRequest,
        proto: App._ServerProto | None = None
    ) -> GNResponse | None:
        path = request.url.path
        method = request.method
        path_candidates = self._build_path_candidates(path)
        candidate_routes = self._collect_candidate_routes(request.route, path_candidates)
        allowed = set()

        for r in candidate_routes:

            if hasattr(request, '_gn_server_proxy_list'):
                if r in request._gn_server_proxy_list: # type: ignore
                    continue

            rid = id(r)

            if self._route_is_static.get(rid, False):
                if r.path_expr not in path_candidates:
                    continue
                path_params: Dict[str, Any] = {}
            else:
                m = self._match_route_path(r, path_candidates)
                if m is None:
                    continue
                path_params = m.groupdict()

            allowed.add(r.method)
            if r.method != method and r.method != '*':
                continue

            params = self._route_param_names[rid]
            annotations = self._route_annotations[rid]
            schema = self._route_schema[rid]
            body_param_names = schema.body_param_names

            resolve_cors(request, r.cors)

            def _ann(name: str):
                return annotations.get(name, inspect._empty)

            kw: dict[str, Any] = {
                name: _convert_value(val, _ann(name), r.param_types.get(name, str))
                for name, val in path_params.items()
                if name not in body_param_names
            }

            for qn, qvals in request.url.params.items():
                if qn in body_param_names:
                    continue
                if qn in kw:
                    continue
                if isinstance(qvals, int):
                    kw[qn] = qvals
                else:
                    raw = qvals if len(qvals) > 1 else qvals[0]
                    kw[qn] = _convert_value(raw, _ann(qn), str)

            
            kw = {k: v for k, v in kw.items() if k in params}

            if schema.body_fields:
                for bf in schema.body_fields:
                    kw.pop(bf.name, None)

                tdo = None
                container = None
                for bf in schema.body_fields:
                    if tdo is None:
                        tdo = await request.tdo
                        container = tdo.container if tdo is not None else None
                    if isinstance(container, DMPContainer) and isinstance(container.payload, dict):
                        if container.version != 0:
                            raise AllGNFastCommands.UnprocessableEntity({
                                'dev_error': f"Parameter '{bf.name}' requires DMP container version 0, got {container.version}",
                                'user_error': f'Server request error {self.domain}'
                            })
                        if container.schema_kind != bf.schema_kind or container.schema_name != bf.schema_name:
                            raise AllGNFastCommands.UnprocessableEntity({
                                'dev_error': (
                                    f"Parameter '{bf.name}' requires DMP schema "
                                    f"kind={bf.schema_kind}, name={bf.schema_name!r}; "
                                    f"got kind={container.schema_kind}, name={container.schema_name!r}"
                                ),
                                'user_error': f'Server request error {self.domain}'
                            })
                        try:
                            kw[bf.name] = model_validate(bf.model_class, container.payload)
                        except (ValidationError, DataModelError) as exc:
                            raise AllGNFastCommands.UnprocessableEntity({
                                'dev_error': (
                                    f"Parameter '{bf.name}' DMP validation failed "
                                    f"({type(exc).__name__}): {exc}"
                                ),
                                'user_error': f'Server request error {self.domain}'
                            }) from exc
                    elif bf.required or not (
                        container is None
                        or (isinstance(container, STPContainer) and container.payload is None)
                    ):
                        raise AllGNFastCommands.UnprocessableEntity({
                            'dev_error': f"Parameter '{bf.name}' requires DMP container (type 5), got {type(container).__name__}",
                            'user_error': f'Server request error {self.domain}'
                        })

            rv = validate_params_by_key(kw, r.handler)
            if rv is not None:
                raise AllGNFastCommands.UnprocessableEntity({'dev_error': rv, 'user_error': f'Server request error {self.domain}'})

            if "request" in params:
                kw["request"] = request

            if "proto" in params:
                kw["proto"] = proto

            try:
                if self._route_is_asyncgen[rid]:
                    return r.handler(**kw)

                result = await r.handler(**kw)
            except ValidationError as exc:
                raise responses.UnprocessableEntity({
                    'dev_error': f"Route '{r.name}' validation failed ({type(exc).__name__}): {exc}",
                    'user_error': f'Server request error {self.domain}'
                }) from exc
            except DataModelValidationError as exc:
                raise responses.UnprocessableEntity({
                    'dev_error': f"Route '{r.name}' DataModel validation failed: {exc}",
                    'user_error': f'Server request error {self.domain}'
                }) from exc
            except DataModelError as exc:
                raise responses.BadRequest({
                    'dev_error': f"Route '{r.name}' DataModel error ({type(exc).__name__}): {exc}",
                    'user_error': f'Server request error {self.domain}'
                }) from exc

            if result is None:
                continue

            if isinstance(result, GNRequest):
                if not hasattr(request, '_gn_server_proxy_list'):
                    result._gn_server_proxy_list = [r]  # type: ignore
                else:
                    result._gn_server_proxy_list.append(r)  # type: ignore
                if self._cors is not None:
                    resolve_cors(request, self._cors)

                return await self.dispatchRequest(result)

            if isinstance(result, (TempDataObject, TempDataGroup)):
                result = responses.ok(result)

            if isinstance(result, GNResponse):
                c = r.cors
                if c is not None:
                    resolve_cors(request, c)
                else:
                    if self._cors is not None:
                        resolve_cors(request, self._cors)

                if result.command.NoResponse:
                    return None

                return result
            else:
                raise TypeError(
                    f"{r.handler.__name__} returned {type(result)}; GNResponse expected"
                )

        if allowed:
            raise AllGNFastCommands.app.MethodNotAllowed({'message': f'Method {method} not allowed for path: {path}'})
        raise AllGNFastCommands.app.PathNotFound({'message': f'Path not found: {path}: request: {request}'})


  

    class _ServerProto(QuicProtocolShell):
        def __init__(self, *a, api: "App", datagramEndpoint: DatagramEndpoint, **kw):
            self._api = api
            self._peer_maddr = None

            super().__init__(*a, datagramEndpoint=datagramEndpoint, client=False, **kw)
            self.setDatagramEndpoint(datagramEndpoint)
            self._quic._gn_pq_datagram_endpoint = self.datagramEndpoint
            self._buffer: Dict[int, bytearray] = {}
            self._streams: Dict[int, Dict[str, Any]] = {}

            self._domain: Optional[str] = cast(Optional[str], self.datagramEndpoint.getDomain(self))
            self._disconnected = False
            self._init_domain = False

            self._refresh_domain()

            asyncio.create_task(self._api.dispatchEvent('connect', proto=self, domain=self._domain))

        def _feed_request_stream(self, stream_id: int, data: bytes, end_stream: bool) -> Optional[GNRequest]:
            state = self._streams.get(stream_id)

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
                    'request': request,
                    'started': True,
                }

                payload_tail = bytes(buf[payload_offset:])
                if payload_tail:
                    request._feedIncomingPayload(payload_tail)

                self._buffer.pop(stream_id, None)
                self._streams[stream_id] = state

                if end_stream:
                    request._finishIncomingPayload(True)
                    self._streams.pop(stream_id, None)

                return request

            request = cast(GNRequest, state['request'])
            if data:
                request._feedIncomingPayload(data)

            if end_stream:
                request._finishIncomingPayload(True)
                self._streams.pop(stream_id, None)

            return None
            
        def quic_event_received(self, event: QuicEvent):
            if isinstance(event, HandshakeCompleted):
                logger.debug(
                    f'[HANDSHAKE] completed domain={self._domain!r} '
                    f'alpn={event.alpn_protocol} resumed={event.session_resumed} '
                    f'early_data={event.early_data_accepted}'
                )
                self.setDefault_max_datagram_size()
                self._refresh_domain()
                domain = self._domain
                self._apply_gn_pq_session_root(domain)

            elif isinstance(event, StreamDataReceived):
                request = self._feed_request_stream(event.stream_id, event.data, event.end_stream)
                if request is not None:
                    asyncio.create_task(self._resolve_request(event.stream_id, request))
            
            elif isinstance(event, StreamReset):
                state = self._streams.pop(event.stream_id, None)
                if state is not None:
                    request = cast(Optional[GNRequest], state.get('request'))
                    if request is not None:
                        request._finishIncomingPayload(False)
                self._buffer.pop(event.stream_id, None)
                logger.warning(
                    f"StreamReset for {self._domain}: stream_id={event.stream_id} "
                    f"error_code={event.error_code}"
                )

            elif isinstance(event, ConnectionTerminated):
                try:
                    error_name = QuicErrorCode(event.error_code).name
                except Exception:
                    error_name = 'UNKNOWN'
                reason = (
                    f"code={event.error_code}({error_name}) frame_type={event.frame_type} "
                    f"reason={event.reason_phrase!r}"
                )
                self._trigger_disconnect(f"ConnectionTerminated: {reason}")
            
            
        def connection_lost(self, exc):
            self._trigger_disconnect(f"Transport closed: {exc!r}")

        def _trigger_disconnect(self, reason: str):
            if self._disconnected:
                return
            self._disconnected = True

            logger.info(f"[DISCONNECT]  — {reason}")

            # release per-connection memory on disconnect
            for state in self._streams.values():
                request = cast(Optional[GNRequest], state.get('request'))
                if request is not None:
                    request._finishIncomingPayload(False)
            self._buffer.clear()
            self._streams.clear()

            if self._domain is not None and self._api.connections.get(self._domain) is self:
                self._api.connections.pop(self._domain, None)

            try:
                self.datagramEndpoint.markProtocolInactive(self)
            except Exception:
                logger.debug('Failed to mark datagram protocol state inactive for disconnected connection')

            try:
                self.datagramEndpoint.dropProtocolState(self)
            except Exception:
                logger.debug('Failed to drop datagram protocol state for disconnected connection')

            
            asyncio.create_task(self._api.dispatchEvent('disconnect', domain=self._domain, L5_reason=reason))

        def _get_connection_encryptor(self):
            if self._peer_maddr is None:
                network_paths = getattr(self._quic, "_network_paths", None)
                if network_paths:
                    addr = network_paths[0].addr
                    self._peer_maddr = DatagramEndpoint.from_addr_to_maddr(addr)

            if self._peer_maddr is None:
                return None

            return self.datagramEndpoint.x_maddr_dgEnc.get(self._peer_maddr)

        def _get_pq_client_domain(self) -> Optional[str]:
            tls_context = getattr(self._quic, 'tls', None)
            if tls_context is None:
                return None

            client_domain = getattr(tls_context, '_gn_pq_authenticated_client_domain', None)
            if isinstance(client_domain, str) and client_domain:
                return client_domain
            return None

        def _refresh_domain(self) -> Optional[str]:
            if self._domain is None:
                self._domain = cast(Optional[str], self.datagramEndpoint.getDomain(self))

            connection_enc = self._get_connection_encryptor()
            pq_client_domain = self._get_pq_client_domain()
            if (
                connection_enc is not None
                and (connection_enc.encryption_type == 2 or connection_enc.keyid[0] == 253)
                and pq_client_domain is not None
                and self._domain != pq_client_domain
            ):
                previous_domain = self._domain
                self._domain = pq_client_domain
                connection_enc.domain = pq_client_domain

                odcid = getattr(self._quic, 'original_destination_connection_id', None)
                if odcid is not None:
                    self.datagramEndpoint.x_cid_domain[odcid] = pq_client_domain

                if previous_domain is not None and self._api.connections.get(previous_domain) is self:
                    self._api.connections.pop(previous_domain, None)

                logger.debug(
                    f"[DOMAIN] Applied GN PQ client domain: {previous_domain!r} -> {pq_client_domain!r}"
                )

            if self._domain is None:
                network_paths = getattr(self._quic, "_network_paths", None)
                if network_paths:
                    addr = network_paths[0].addr
                    maddr = DatagramEndpoint.from_addr_to_maddr(addr)
                    self._domain = Url.ip_and_port_to_ipv6_with_port(maddr[0], maddr[1])
                    logger.warning(f"[DOMAIN] Missing CID mapping, fallback domain used: {self._domain}")

            if self._domain is not None and self._api.connections.get(self._domain) is not self:
                self._api.connections[self._domain] = self

            if self._peer_maddr is None:
                network_paths = getattr(self._quic, "_network_paths", None)
                if network_paths:
                    addr = network_paths[0].addr
                    self._peer_maddr = DatagramEndpoint.from_addr_to_maddr(addr)

            return self._domain

        async def _resolve_request(self, stream_id: int, request: GNRequest):
            try:
                self._refresh_domain()

                await self._resolve_dev_transport_request(request)

                if self._domain is None:
                    network_paths = getattr(self._quic, "_network_paths", None)
                    remote_addr = network_paths[0].addr if network_paths else 'unknown'
                    asyncio.create_task(self.sendRawResponse(stream_id, GNResponse('error', {'error': f'domain not set {remote_addr}'})))
                    return

                request.client._data['domain'] = self._domain

                network_paths = getattr(self._quic, "_network_paths", None)
                request.client._data['remote_addr'] = network_paths[0].addr if network_paths else None
                request.stream_id = stream_id   # type: ignore

                request._assembly_server()
                await self._handle_request(request)
            except Exception:
                logger.error('Raw request resolve error:\n' + traceback.format_exc())
                try:
                    await self.sendRawResponse(stream_id, AllGNFastCommands.InternalServerError())
                except Exception:
                    logger.error('Raw request error response failed:\n' + traceback.format_exc())
            finally:
                self._buffer.pop(stream_id, None)
                state = self._streams.get(stream_id)
                if state is not None and state.get('request') is request:
                    payload_state = request._payload_state
                    if (
                        payload_state.payloadComplete
                        or payload_state.payloadIncomplete
                    ):
                        self._streams.pop(stream_id, None)

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
            
            if not request.transportObject.routeProtocol.dev:
                return

            if request.cookies is None:
                return
            
            # gn_ = request.cookies.get('gn')
            # if gn_ is not None:
            #     if response._cookies is None:
            #         response._cookies = {}
            #     response._cookies['gn'] = gn_


            data: dict | None = response.cookies.get('gn', {}).get('request', {}).get('transport', {}).get('::dev')
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
                response = await self._api.dispatchRequest(request, self)

                if response is None:
                    return

                if not isinstance(response, GNResponse):
                    await self.sendResponseFromRequest(request, AllGNFastCommands.InternalServerError(
                        {'message': f'Invalid response type: {type(response)}'}
                    ))
                    return

                await self.sendResponseFromRequest(request, response)
            except Exception as e:
                if isinstance(e, (GNResponse, GNFastCommand)):
                    await self.sendResponseFromRequest(request, e)
                else:
                    logger.error('InternalServerError:\n'  + traceback.format_exc())
                    await self.sendResponseFromRequest(request, AllGNFastCommands.InternalServerError())
            

        
        async def sendResponseFromRequest(self, request: GNRequest, response: GNResponse, end_stream: bool = True):
            """
            Отправляет ответ клиенту. Клиент получит ответ на тот же stream_id, что и запрос. Закрывая запрос.
            """
            await self._resolve_dev_transport_response(response, request)

            logger.info(f'[>] [{request.client.domain}] Response: {request.method} {request.url} -> {response.command}')

            if request.stream_id not in self._quic._streams:
                logger.warning(f"Stream {request.stream_id} not found for response, skipping send")
                return
            
            await self.sendRawResponse(request.stream_id, response=response, end_stream=end_stream)  # type: ignore

        async def sendRawResponse(self, stream_id: int, response: GNResponse, end_stream: bool = True):
            header = response.serializeHeader()
            has_payload = response.hasPayload
            stream_finished = False

            try:
                self._quic.send_stream_data(stream_id, header, end_stream=end_stream and not has_payload) # type: ignore
                self.transmit()
                await self._drain_stream_send_buffer(stream_id)

                if not has_payload:
                    stream_finished = end_stream
                    return

                async for chunk in response.iterSerializedPayload(self.datagramEndpoint.DEPConfig.iter_payload_chunk_size):
                    self._quic.send_stream_data(stream_id, chunk, end_stream=False) # type: ignore
                    self.transmit()
                    await self._drain_stream_send_buffer(stream_id)

                if end_stream:
                    self._quic.send_stream_data(stream_id, b'', end_stream=True) # type: ignore
                    self.transmit()
                    stream_finished = True
                    await self._drain_stream_send_buffer(stream_id)
            except BaseException:
                if not stream_finished:
                    self._reset_stream_after_send_error(stream_id, 'sendRawResponse')
                raise
        
        async def sendRequest(self, request: GNRequest, end_stream: bool = True):
            sid = self._quic.get_next_available_stream_id()
            header = request.serializeHeader()
            has_payload = request.hasPayload
            stream_finished = False

            try:
                self._quic.send_stream_data(sid, header, end_stream=end_stream and not has_payload)
                self.transmit()
                await self._drain_stream_send_buffer(sid)

                if not has_payload:
                    stream_finished = end_stream
                    return

                async for chunk in request.iterSerializedPayload(self.datagramEndpoint.DEPConfig.iter_payload_chunk_size):
                    self._quic.send_stream_data(sid, chunk, end_stream=False)
                    self.transmit()
                    await self._drain_stream_send_buffer(sid)

                if end_stream:
                    self._quic.send_stream_data(sid, b'', end_stream=True)
                    self.transmit()
                    stream_finished = True
                    await self._drain_stream_send_buffer(sid)
            except BaseException:
                if not stream_finished:
                    self._reset_stream_after_send_error(sid, 'sendRequest')
                raise

        def _reset_stream_after_send_error(self, stream_id: int, source: str) -> None:
            try:
                self._quic.reset_stream(stream_id, QuicErrorCode.INTERNAL_ERROR)
                self.transmit()
            except Exception:
                logger.debug(f'{source}: failed to reset stream {stream_id} after send error')

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

                quic_server = GNQuicServer(
                    configuration=cfg,
                    create_protocol=proto_factory,
                    gn_pq_server_settings=getattr(self, '_gn_pq_server_settings', None),
                )

                self._datagramEndpoint = DatagramEndpoint(quic_server, self.client._kdc, dEPConfig=self.DEPConfig)
                self._datagramEndpoint._domain = domain


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

    def fastFile(self, path: str, file_path: str | Path, cors: CORSObject | None = None):
        path = path.strip()
        if not path:
            path = '/'
        if not path.startswith('/'):
            path = f'/{path}'
        if len(path) > 1 and path.endswith('/'):
            path = path[:-1]

        if isinstance(file_path, Path):
            file_path = str(file_path)
        if file_path.endswith('/') and file_path != '/':
            file_path = file_path[:-1]

        @self.get(path, cors=cors) # type: ignore
        async def r_static():
            return responses.ok(_path_to_iter_tdo(file_path, self.DEPConfig.iter_payload_chunk_size))
            

    def staticDir(self, path: str, dir_path: str | Path, cors: CORSObject | None = None):
        if isinstance(dir_path, Path):
            dir_path = str(dir_path)

        path = path.strip()
        if not path:
            path = '/'
        if not path.startswith('/'):
            path = f'/{path}'
        if len(path) > 1 and path.endswith('/'):
            path = path[:-1]

        wildcard_path = f"{path}/{{_path:path}}" if path != '/' else "/{_path:path}"

        @self.get(wildcard_path, cors=cors)  # type: ignore
        async def r_static(_path: str):
            file_path = os.path.join(dir_path, _path)
            
            if file_path.endswith('/') and file_path != '/':
                file_path = file_path[:-1]
                
            return responses.ok(_path_to_iter_tdo(file_path, self.DEPConfig.iter_payload_chunk_size))

    def _init_sys_routes(self):
        @self.route('post', '/!gn-vm-host/ping', cors=CORSObject(allow_client_types=['local']))
        async def _(request: GNRequest):
            return responses.ok({'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 't': datetime.datetime.now(datetime.timezone.utc)})

        @self.route('post', '/response', route='gn:shield-origin:response')
        async def _(request: GNRequest):
            if request.client.domain != '*~api.origin.shield.gn':
                raise AllGNFastCommands.app.Rejected(request.client.domain)

            c = cast(dict, request.cookies)
            request_id: int = c['id']
            header_bytes: bytes = c['header']

            parsed = GNResponse.try_deserialize_header(header_bytes)
            if parsed is None:
                raise AllGNFastCommands.app.BadRequest({'message': 'Invalid response header in shield-origin response'})
            resp, _, _ = parsed

            f = self._togn_requests_inflight.get(request_id, None)
            if f is not None:
                if not f.done():
                    f.set_result(resp)
            else:
                logger.warning(f"requestToGN: ответ с id {request_id} не найден среди inflight-запросов")

            complete = True
            try:
                async for chunk in request.iter.raw(self.DEPConfig.iter_payload_chunk_size):
                    if chunk is None:
                        complete = False
                        break
                    resp._feedIncomingPayload(chunk)
            except Exception:
                complete = False
                raise
            finally:
                resp._finishIncomingPayload(complete)

            return AllGNFastCommands.ok()


logger.info(f'PID: {os.getpid()}')
