
import re
from typing import Optional
from urllib.parse import urlparse
from gnobjects.net.objects import GNRequest, CORSObject
from gnobjects.net.fastcommands import AllGNFastCommands

def _resolve_cors(origin_url: str, rules: list[str]) -> bool:
    """
    Возвращает origin_url если он матчится хотя бы с одним правилом.
    Правила:
      - "*.example.com"    -> wildcard (одна метка)
      - "**.example.com"   -> globstar (0+ меток)
      - "pages.*.core.gn"  -> смешанное
      - "gn://*.site.tld" -> с проверкой схемы
      - "!<regex>"         -> полное соответствие по regex к origin_url
    """

    if origin_url == 'gn:proxy:sys':
        return True

    if rules in ('*', ['*']):
        return True



    origin = origin_url.rstrip("/")
    pu = urlparse(origin)
    scheme = (pu.scheme or "").lower()
    host = (pu.hostname or "").lower()
    port = pu.port  # может быть None

    if not host:
        return False

    for rule in rules:
        rule = rule.rstrip("/")

        # 1) Регекс-правило
        if rule.startswith("!"):
            pattern = rule[1:]
            if re.fullmatch(pattern, origin):
                return True
            continue

        # 2) Разбор схемы/хоста в правиле
        r_scheme = ""
        r_host = ""
        r_port = None

        if "://" in rule:
            pr = urlparse(rule)
            r_scheme = (pr.scheme or "").lower()
            # pr.netloc может содержать порт
            netloc = pr.netloc.lower()
            # разберём порт, если есть
            if ":" in netloc and not netloc.endswith("]"):  # простая обработка IPv6 не требуется здесь
                name, _, p = netloc.rpartition(":")
                r_host = name
                try:
                    r_port = int(p)
                except ValueError:
                    r_port = None
            else:
                r_host = netloc
        else:
            r_host = rule.lower()

        # схема в правиле задана -> должна совпасть
        if r_scheme and r_scheme != scheme:
            continue
        # порт в правиле задан -> должен совпасть
        if r_port is not None and r_port != port:
            continue

        # 3) Сопоставление хоста по шаблону с * и ** (по меткам)
        if _host_matches_pattern(host, r_host):
            return True

    return False

def _host_matches_pattern(host: str, pattern: str) -> bool:
    """
    Матчит host против pattern по доменным меткам:
      - '*'  -> ровно одна метка
      - '**' -> ноль или больше меток
      Остальные метки — точное совпадение (без внутр. вайлдкардов).
    Примеры:
      host=pages.static.core.gn, pattern=**.core.gn -> True
      host=pages.static.core.gn, pattern=pages.*.core.gn -> True
      host=pages.static.core.gn, pattern=*.gn.gn -> False
      host=abc.def.example.com, pattern=*.example.com -> False (нужно **.example.com)
      host=abc.example.com,     pattern=*.example.com -> True
    """
    host_labels = host.split(".")
    pat_labels = pattern.split(".")

    # быстрый путь: точное совпадение без вайлдкардов
    if "*" not in pattern:
        return host == pattern

    # рекурсивный матч с поддержкой ** (globstar)
    def match(hi: int, pi: int) -> bool:
        # оба дошли до конца
        if pi == len(pat_labels) and hi == len(host_labels):
            return True
        # закончился паттерн — нет
        if pi == len(pat_labels):
            return False

        token = pat_labels[pi]
        if token == "**":
            # два варианта:
            #  - пропустить '**' (ноль меток)
            if match(hi, pi + 1):
                return True
            #  - съесть одну метку (если есть) и остаться на '**'
            if hi < len(host_labels) and match(hi + 1, pi):
                return True
            return False
        elif token == "*":
            # нужно съесть ровно одну метку
            if hi < len(host_labels):
                return match(hi + 1, pi + 1)
            return False
        else:
            # точное совпадение метки
            if hi < len(host_labels) and host_labels[hi] == token:
                return match(hi + 1, pi + 1)
            return False

    return match(0, 0)



def resolve_cors(request: GNRequest, cors: Optional[CORSObject]):
    if cors is None:
        return
    
    if request.client.type not in cors.allow_client_types and request.client.type_int != 0:
        raise AllGNFastCommands.cors.ClientTypeNotAllowed()
    
    if cors.allow_origins is not None:
        if request._origin is None:
            raise AllGNFastCommands.cors.OriginNotAllowed('Route has cors but request has no origin url')

        if not _resolve_cors(request._origin, cors.allow_origins):
            raise AllGNFastCommands.cors.OriginNotAllowed()

    if cors.allow_methods is not None:
        if request.method not in cors.allow_methods:
            raise AllGNFastCommands.cors.MethodNotAllowed()
        
    if cors.allow_transport_protocols is not None:
        if request.transport in ('gn:quik:real', 'gn:quik:dev') and request.transport not in cors.allow_transport_protocols:
            raise AllGNFastCommands.cors.TransportProtocolNotAllowed()
