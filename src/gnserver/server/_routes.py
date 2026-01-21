
import re
import uuid
import decimal
import inspect
import datetime
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple, Union, AsyncGenerator
from dataclasses import dataclass
from typing import Any, Union, get_origin, get_args


from gnobjects.net.objects import CORSObject

@dataclass
class Route:
    route: str
    method: str
    path_expr: str
    regex: Pattern[str]
    param_types: dict[str, Callable[[str], Any]]
    handler: Callable[..., Any]
    name: str
    cors: Optional[CORSObject]

_PARAM_REGEX: dict[str, str] = {
    "str":   r"[^/]+",
    "path":  r".+",
    "int":   r"\d+",
    "float": r"[+-]?\d+(?:\.\d+)?",
    "bool":  r"(?:true|false|1|0)",
    "uuid":  r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
             r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
             r"[0-9a-fA-F]{12}",
    "datetime": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?",
    "date":     r"\d{4}-\d{2}-\d{2}",
    "time":     r"\d{2}:\d{2}:\d{2}(?:\.\d+)?",
    "decimal":  r"[+-]?\d+(?:\.\d+)?",
}

_CONVERTER_FUNC: dict[str, Callable[[str], Any]] = {
    "int":     int,
    "float":   float,
    "bool":    lambda s: s.lower() in {"1","true","yes","on"},
    "uuid":    uuid.UUID,
    "decimal": decimal.Decimal,
    "datetime": datetime.datetime.fromisoformat,
    "date":     datetime.date.fromisoformat,
    "time":     datetime.time.fromisoformat,
}

def _compile_path(path: str) -> tuple[Pattern[str], dict[str, Callable[[str], Any]]]:
    if path == '*':
        return re.compile('.' + path), {}
    if path[0] == '!':
        path = path[1:]
        return re.compile(path), {}
    param_types: dict[str, Callable[[str], Any]] = {}
    rx_parts: list[str] = ["^"]
    i = 0
    while i < len(path):
        if path[i] != "{":
            rx_parts.append(re.escape(path[i]))
            i += 1
            continue
        j = path.index("}", i)
        spec = path[i+1:j]
        i = j + 1

        if ":" in spec:
            name, conv = spec.split(":", 1)
        else:
            name, conv = spec, "str"

        if conv.startswith("^"):
            rx = f"(?P<{name}>{conv})"
            typ = str
        else:
            rx = f"(?P<{name}>{_PARAM_REGEX.get(conv, _PARAM_REGEX['str'])})"
            typ = _CONVERTER_FUNC.get(conv, str)

        rx_parts.append(rx)
        param_types[name] = typ

    rx_parts.append("$")
    return re.compile("".join(rx_parts)), param_types

def _convert_value(raw: str | list[str], ann: Any, fallback: Callable[[str], Any]) -> Any:
    origin = get_origin(ann)
    args   = get_args(ann)

    if isinstance(raw, list) or origin is list:
        subtype = args[0] if (origin is list and args) else str
        if not isinstance(raw, list):
            raw = [raw]
        return [_convert_value(r, subtype, fallback) for r in raw]

    if origin is Union:
        for subtype in args:
            try:
                return _convert_value(raw, subtype, fallback)
            except Exception:
                continue
        return raw  # если ни один тип не подошёл

    conv = _CONVERTER_FUNC.get(ann, ann) if ann is not inspect._empty else fallback
    return conv(raw) if callable(conv) else raw

def _ensure_async(fn: Callable[..., Any]) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(fn) or inspect.isasyncgenfunction(fn):
        return fn
    async def wrapper(*args, **kw):
        return fn(*args, **kw)
    return wrapper