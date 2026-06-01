from collections import OrderedDict
from dataclasses import dataclass
from typing import Awaitable, List, Optional, Dict, Union, Set, TYPE_CHECKING, Callable, Coroutine
from gnobjects.net.objects import Url, GNRequest, GNResponse
from gnobjects.net.fastcommands import AllGNFastCommands
import inspect
from typing import List, Optional, Dict, Union, Set, Deque, Tuple, cast
from pathlib import Path

from gnobjects.net.tools import DomainMatcherList

if TYPE_CHECKING:
    from .client._client import AsyncClient


import logging
logger = logging.getLogger("GNServer.DatagramEndpoint.KDC")



@dataclass(slots=True)
class InactiveTransportSession:
    domain: str
    keyid: Tuple[int, int]
    encryption_type: int
    root64: bytes

class KDCObject:
    @staticmethod
    def isKDCKeyTypeSupported(key_type: int) -> bool:
        return key_type in (0, 251, 253, 255) or 1 <= key_type <= 100

    @classmethod
    def isKDCKeyIdSupported(cls, keyid: Tuple[int, int]) -> bool:
        return cls.isKDCKeyTypeSupported(keyid[0])

    @staticmethod
    def _unsupported_key_type_payload(keyid: Tuple[int, int], **details) -> dict:
        payload = {
            'keyid': keyid,
            'key_type': keyid[0],
            'supported_key_types': ['0', '1-100', '251', '253', '255'],
        }
        payload.update(details)
        return payload

    def __init__(self, client: 'AsyncClient'):
     
        self._client = client

        self._x_domain_keyId: Dict[str, Tuple[int, int]] = {}
        self._x_keyId_key: Dict[Tuple[int, int], bytes] = {}

        self._encryption_type: Dict[Union[str, int], int] = {}
        self._domain_hkdf_cache: Dict[Tuple[int, str], bytes] = {}
        self._inactive_transport_sessions: OrderedDict[str, InactiveTransportSession] = OrderedDict()
        self._inactive_transport_sessions_keyid_domain: Dict[Tuple[int, int], str] = {}

        self.second_kdc_domains_patterns: Optional[DomainMatcherList] = None
        self._kdc_domain: Optional[str] = None
        self._kdc_domain_id: Optional[Tuple[int, int]] = None
        self._second_kdc_domain: Optional[str] = None
        self._second_kdc_domain_id: Optional[Tuple[int, int]] = None
        self._active_key_synchronization = True
        self.__active_key_synchronization_callback = None
        self.__active_key_synchronization_callback_is_async = False
        self._active_key_synchronization_df = None

    def init(self,
             gn_crt: Optional[Union[bytes, str, Path, dict]] = None,
             requested_domains: Optional[List[str]] = None,
             active_key_synchronization: bool = True,
             active_key_synchronization_callback: Callable[
                                                            [list[str | tuple[int, int]]],
                                                            list[tuple[tuple[int, int], str, bytes] | bool]
                                                            | Awaitable[list[tuple[tuple[int, int], str, bytes] | bool]]
                                                        ] | None = None,
             active_key_synchronization_callback_domainFilter: list[str] | None = None
             ):
        if gn_crt is None:
            gn_crt = self._client._gn_crt_data

        if not isinstance(gn_crt, dict):
            from .server._gnserver import GNServer as _gnserver

            self._gn_crt_data = _gnserver._get_gn_server_crt(gn_crt, self._domain)
        else:
            self._gn_crt_data = gn_crt

        crypto = self._gn_crt_data.get('crypto')
        if not isinstance(crypto, dict):
            raise ValueError('gn_server_crt.crypto must be dict')

        self._domain: str = self._gn_crt_data['domain']
        self._requested_domains = list(requested_domains or [])
        self._active_key_synchronization = active_key_synchronization

        self.__active_key_synchronization_callback = active_key_synchronization_callback
        self.__active_key_synchronization_callback_is_async = inspect.iscoroutinefunction(active_key_synchronization_callback)

        if active_key_synchronization_callback is not None and active_key_synchronization_callback_domainFilter is not None:
            self._active_key_synchronization_df = DomainMatcherList(active_key_synchronization_callback_domainFilter)
        else:
            self._active_key_synchronization_df = None

        kdc = crypto.get('kdc')
        self._kdc_domain = None
        self._kdc_domain_id = None
        self._second_kdc_domain = None
        self._second_kdc_domain_id = None

        if kdc is None:
            return
        if not isinstance(kdc, dict):
            raise ValueError('gn_server_crt.crypto.kdc must be dict or None')

        kdc_domain = kdc['domain']
        kdc_domain_id = (255, kdc['self_domain_id'])
        self._kdc_domain = kdc_domain
        self._kdc_domain_id = kdc_domain_id

        self._x_domain_keyId[kdc_domain] = kdc_domain_id
        self._x_keyId_key[kdc_domain_id] = kdc['key']


        self._second_kdc_domain = kdc.get('second_domain')
        second_self_domain_id = kdc.get('second_self_domain_id')
        self._second_kdc_domain_id: Optional[Tuple[int, int]] = (255, second_self_domain_id) if second_self_domain_id else None
        # 255, потому что это ключ к kdc. там не 251, даже для второго

        if self._second_kdc_domain is not None and self._second_kdc_domain_id is not None:
            self._x_domain_keyId[self._second_kdc_domain] = self._second_kdc_domain_id
            self._x_keyId_key[self._second_kdc_domain_id] = kdc['second_key']

        # если запросим второй kdc, а в crt только 1, то попробуем прокинуть первый как второй. Упрощение для core серверов.
        if self._second_kdc_domain is None and self._second_kdc_domain_id is None:
            self._second_kdc_domain = kdc_domain
            self._second_kdc_domain_id = kdc_domain_id
            self._x_domain_keyId[kdc_domain] = kdc_domain_id
            self._x_keyId_key[kdc_domain_id] = kdc['key']

    def hasConfiguredKDC(self) -> bool:
        return self._kdc_domain is not None and self._kdc_domain_id is not None

    def _require_kdc_config(self) -> None:
        if not self.hasConfiguredKDC():
            raise ValueError('KDC is not configured for gn_server_crt')

    def setDomainEcryptionType(self, domain_or_keyId: Union[str, int], type: int = 1) -> None:
        self._encryption_type[domain_or_keyId] = type
        # 0 = TLS only (no PQ, no KDC)
        # 1 = KDC + PQ + TLS (default for named domains)
        # 2 = PQ + TLS (no KDC, default for IP connections)
    def getDomainEcryptionType(self, domain_or_keyId: Union[str, int]) -> Optional[int]:
        return self._encryption_type.get(domain_or_keyId)

    async def addServers(self, servers_keys: Optional[List[Tuple[Union[Tuple[int, int], int], str, bytes]]] = None,
                   requested_domains: Optional[List[str]] = None): # type: ignore
        if requested_domains is not None:
            self._requested_domains += requested_domains

        if servers_keys is not None:
            for i in list(self._requested_domains):
                for (kid, domain, key) in servers_keys:
                    if i == domain:
                        self._requested_domains.remove(i)

            for (kid, domain, key) in servers_keys:
                kid = cast(Tuple[int, int], tuple(kid) if isinstance(kid, (tuple, list)) else (0, kid))
                self._x_domain_keyId[domain] = kid
                self._x_keyId_key[kid] = key

        

        if len(self._requested_domains) > 0:
            await self.requestKDC(self._requested_domains) # type: ignore

    async def requestKDC(self, domain_or_keyId: Union[str, Tuple[int, int], List[Union[str, Tuple[int, int]]]]):

        if not isinstance(domain_or_keyId, list):
            domain_or_keyId = [domain_or_keyId]

        out = []

        c = []
        r = []
        has_active_callback = (
            self._active_key_synchronization_df is not None
            and self.__active_key_synchronization_callback is not None
        )

        for d_or_id in domain_or_keyId:
            if not isinstance(d_or_id, str):
                keyid = cast(Tuple[int, int], tuple(d_or_id))
                if has_active_callback and 'int' in self._active_key_synchronization_df.literal:
                    c.append(keyid)
                elif self.isKDCKeyIdSupported(keyid):
                    r.append(keyid)
                else:
                    raise AllGNFastCommands.transport.UnsupportedKeyType(
                        self._unsupported_key_type_payload(keyid, source='request_kdc')
                    )
            else:
                if has_active_callback and self._active_key_synchronization_df.match_any(d_or_id):
                    c.append(d_or_id)
                else:
                    r.append(d_or_id)

        if c:
            try:
                if self.__active_key_synchronization_callback_is_async:
                    a = await self.__active_key_synchronization_callback(c) # type: ignore
                else:
                    a = self.__active_key_synchronization_callback(c)
            except Exception as exc:
                for item in c:
                    if not isinstance(item, str) and not self.isKDCKeyIdSupported(item):
                        raise AllGNFastCommands.transport.UnsupportedKeyType(
                            self._unsupported_key_type_payload(
                                item,
                                source='active_key_synchronization_callback',
                                reason='callback_exception',
                                exception_type=type(exc).__name__,
                                exception=str(exc),
                            )
                        )
                raise

            if not isinstance(a, list):
                for item in c:
                    if not isinstance(item, str) and not self.isKDCKeyIdSupported(item):
                        raise AllGNFastCommands.transport.UnsupportedKeyType(
                            self._unsupported_key_type_payload(
                                item,
                                source='active_key_synchronization_callback',
                                reason='callback_returned_none' if a is None else 'callback_invalid_response',
                            )
                        )
                raise AllGNFastCommands.kdc.InvalidResponseFormat('active_key_synchronization_callback must return list')

            for item in c[len(a):]:
                if not isinstance(item, str) and not self.isKDCKeyIdSupported(item):
                    raise AllGNFastCommands.transport.UnsupportedKeyType(
                        self._unsupported_key_type_payload(
                            item,
                            source='active_key_synchronization_callback',
                            reason='callback_missing_result',
                        )
                    )
            
            for i, x in enumerate(a):
                source_item = c[i] if i < len(c) else None
                source_keyid = source_item if not isinstance(source_item, str) else None

                if isinstance(x, bool):
                    if source_item is None:
                        raise AllGNFastCommands.kdc.InvalidResponseFormat(
                            'active_key_synchronization_callback returned more boolean results than requested keys'
                        )
                    if x:
                        if source_keyid is not None and not self.isKDCKeyIdSupported(source_keyid):
                            raise AllGNFastCommands.transport.UnsupportedKeyType(
                                self._unsupported_key_type_payload(
                                    source_keyid,
                                    source='active_key_synchronization_callback',
                                    reason='callback_requested_kdc_for_unsupported_key_type',
                                )
                            )
                        r.append(source_item)
                    elif source_keyid is not None and not self.isKDCKeyIdSupported(source_keyid):
                        raise AllGNFastCommands.transport.UnsupportedKeyType(
                            self._unsupported_key_type_payload(
                                source_keyid,
                                source='active_key_synchronization_callback',
                                reason='callback_declined_key',
                            )
                        )
                    continue

                if x is None or isinstance(x, GNResponse):
                    if source_keyid is not None and not self.isKDCKeyIdSupported(source_keyid):
                        details = {'reason': 'callback_returned_none' if x is None else 'callback_returned_error'}
                        if isinstance(x, GNResponse):
                            details['command'] = str(x.command)
                        raise AllGNFastCommands.transport.UnsupportedKeyType(
                            self._unsupported_key_type_payload(
                                source_keyid,
                                source='active_key_synchronization_callback',
                                **details,
                            )
                        )
                    if x is None:
                        raise AllGNFastCommands.kdc.InvalidResponseFormat(
                            'active_key_synchronization_callback returned None for requested key'
                        )
                    raise x

                out.append(x)

        if r:
            unsupported = [
                item for item in r
                if not isinstance(item, str) and not self.isKDCKeyIdSupported(cast(Tuple[int, int], item))
            ]
            if unsupported:
                keyid = cast(Tuple[int, int], unsupported[0])
                raise AllGNFastCommands.transport.UnsupportedKeyType(
                    self._unsupported_key_type_payload(keyid, source='request_kdc')
                )

            res = await self._requestKDC(r)
            out.extend(res)
        

        for (keyId, domain, key) in out:
            keyId = tuple(keyId) if isinstance(keyId, (tuple, list)) else (0, keyId)
            self._x_domain_keyId[domain] = keyId
            self._x_keyId_key[keyId] = key
            logger.debug(f'KDC: Добавлены ключи domain: {domain}, keyId: {keyId}')

    async def _requestKDC(self, domain_or_keyId: List[Union[str, Tuple[int, int]]]):
        self._require_kdc_config()
        logger.debug(f'RAW: start kdc request to [{domain_or_keyId}]')

        d = self._kdc_domain

        if all(isinstance(d, str) for d in domain_or_keyId): # List[str]
            if self.second_kdc_domains_patterns is not None:
                if self.second_kdc_domains_patterns.match_any(cast(str, domain_or_keyId[0])):
                    d = self._second_kdc_domain
            
        else: # List[Tuple[int, int]]
            if domain_or_keyId[0][0] == 251:
                # тип ключа 251 это для использования глобального kdc
                d = self._second_kdc_domain
            

        rs = await self._client.request(GNRequest('get', Url(f'gn://{d}/api/sys/server/keys'),
                                                payload=domain_or_keyId), keep_alive=self._active_key_synchronization)
        logger.debug('RAW: END kdc request')

        rs_payload = await rs.payload

        if not rs.command.ok:
            logger.error(f'ERROR: {rs.command} {rs_payload}')
            raise rs
        
        if not isinstance(rs_payload, list):
            logger.error(f'command.value -> {rs.command.value}. ok: {bool(rs.command.ok)}, app: {bool(rs.command.app)}, cors: {bool(rs.command.cors)}, dns: {bool(rs.command.dns)}, dns.DomainBlocked: {bool(rs.command.dns.DomainBlocked)}, Forbidden: {bool(rs.command.Forbidden)}, app.Forbidden: {bool(rs.command.app.Forbidden)}')
            raise AllGNFastCommands.kdc.InvalidResponseFormat(f'r.payload is not list. {type(rs_payload)} -> {rs_payload}')

        return rs_payload

    def getKey(self, domain_or_keyId: Union[str, Tuple[int, int]]) -> bytes:
        if isinstance(domain_or_keyId, str):
            return self._x_keyId_key[self._x_domain_keyId[domain_or_keyId]]
        else:
            return self._x_keyId_key.get(domain_or_keyId) # type: ignore

    def getDomainById(self, keyId: Tuple[int, int]) -> Optional[str]:
        for d, k in self._x_domain_keyId.items():
            if k == keyId:
                return d
        return None
    
    def getKeyIdByDomain(self, domain: str) -> Optional[Tuple[int, int]]:
        return self._x_domain_keyId.get(domain) # type: ignore

    async def requestKeyIfNotExist(self, domain_or_keyId: Union[List[Union[str, Tuple[int, int]]], str, Tuple[int, int]]):
        if isinstance(domain_or_keyId, str):
            if domain_or_keyId not in self._x_domain_keyId:
                await self.requestKDC(domain_or_keyId)
        else:
            if domain_or_keyId not in self._x_keyId_key:
                await self.requestKDC(domain_or_keyId)

    def rememberInactiveTransportSession(
        self,
        *,
        domain: str,
        keyid: Tuple[int, int],
        encryption_type: int,
        root64: bytes,
        max_sessions: int = 8192,
    ) -> None:
        if not domain or encryption_type == 0 or len(root64) != 64:
            return

        existing = self._inactive_transport_sessions.pop(domain, None)
        if existing is not None:
            self._inactive_transport_sessions_keyid_domain.pop(existing.keyid, None)

        previous_domain = self._inactive_transport_sessions_keyid_domain.pop(keyid, None)
        if previous_domain is not None and previous_domain != domain:
            self._inactive_transport_sessions.pop(previous_domain, None)

        session = InactiveTransportSession(
            domain=domain,
            keyid=keyid,
            encryption_type=encryption_type,
            root64=root64,
        )
        self._inactive_transport_sessions[domain] = session
        self._inactive_transport_sessions_keyid_domain[keyid] = domain

        limit = max(1, int(max_sessions or 1))
        while len(self._inactive_transport_sessions) > limit:
            expired_domain, expired_session = self._inactive_transport_sessions.popitem(last=False)
            if self._inactive_transport_sessions_keyid_domain.get(expired_session.keyid) == expired_domain:
                self._inactive_transport_sessions_keyid_domain.pop(expired_session.keyid, None)

    def getInactiveTransportSessionByDomain(self, domain: str) -> Optional[InactiveTransportSession]:
        session = self._inactive_transport_sessions.get(domain)
        if session is None:
            return None

        self._inactive_transport_sessions.move_to_end(domain)
        return session

    def getInactiveTransportSessionByKeyId(self, keyid: Tuple[int, int]) -> Optional[InactiveTransportSession]:
        domain = self._inactive_transport_sessions_keyid_domain.get(keyid)
        if domain is None:
            return None

        session = self._inactive_transport_sessions.get(domain)
        if session is None:
            self._inactive_transport_sessions_keyid_domain.pop(keyid, None)
            return None

        self._inactive_transport_sessions.move_to_end(domain)
        return session

    def deleteInactiveTransportSession(self, domain_or_keyid: Union[str, Tuple[int, int]]) -> None:
        if isinstance(domain_or_keyid, str):
            session = self._inactive_transport_sessions.pop(domain_or_keyid, None)
            if session is not None and self._inactive_transport_sessions_keyid_domain.get(session.keyid) == domain_or_keyid:
                self._inactive_transport_sessions_keyid_domain.pop(session.keyid, None)
            return

        domain = self._inactive_transport_sessions_keyid_domain.pop(domain_or_keyid, None)
        if domain is not None:
            self._inactive_transport_sessions.pop(domain, None)

    def clearInactiveTransportSessions(self) -> None:
        self._inactive_transport_sessions.clear()
        self._inactive_transport_sessions_keyid_domain.clear()
    
    def deleteKeyByDomain(self, domain: str) -> None:
        keyid = self._x_domain_keyId.pop(domain, None)

        if keyid is None:
            return
        
        self._x_keyId_key.pop(keyid)





