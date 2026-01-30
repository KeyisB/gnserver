from typing import List, Optional, Dict, Union, Set, TYPE_CHECKING, Callable, Coroutine
from gnobjects.net.objects import Url, GNRequest
import inspect
from typing import List, Optional, Dict, Union, Set, Deque, Tuple, cast
from pathlib import Path

from gnobjects.net.tools import DomainMatcherList

if TYPE_CHECKING:
    from .client._client import AsyncClient

class KDCObject:
    def __init__(self, client: 'AsyncClient'):
     
        self._client = client

        self._x_domain_keyId: Dict[str, Tuple[int, int]] = {}
        self._x_keyId_key: Dict[Tuple[int, int], bytes] = {}

        self._encryption_type: Dict[Union[str, int], int] = {}
        self._domain_hkdf_cache: Dict[Tuple[int, str], bytes] = {}

    def init(self,
             gn_crt: Optional[Union[bytes, str, Path, dict]] = None,
             requested_domains: List[str] = [],
             active_key_synchronization: bool = True,
             active_key_synchronization_callback: Optional[Callable[[List[Union[str, int]]], Union[List[Tuple[int, str, bytes]], Coroutine]]] = None,
             active_key_synchronization_callback_domainFilter: Optional[List[str]] = None
             ):
        if gn_crt is None:
            gn_crt = self._client._gn_crt_data

        if not isinstance(gn_crt, dict):
            from .server._gnserver import GNServer as _gnserver

            self._gn_crt_data = _gnserver._get_gn_server_crt(gn_crt, self._domain)
        else:
            self._gn_crt_data = gn_crt

        self._domain: str = self._gn_crt_data['domain']
        self._kdc_domain: str = self._gn_crt_data['kdc_domain']
        self._kdc_domain_id: str = (255, self._gn_crt_data['kdc_domain_id']) # type: ignore

        
        self._x_domain_keyId[self._kdc_domain] = self._kdc_domain_id # type: ignore
        self._x_keyId_key[self._kdc_domain_id] = self._gn_crt_data['kdc_key'] # type: ignore
        

        self._requested_domains = requested_domains
        self._active_key_synchronization = active_key_synchronization

        
        self.active_key_synchronization_callback = active_key_synchronization_callback
        self.active_key_synchronization_callback_is_async = inspect.iscoroutinefunction(active_key_synchronization_callback)

        if active_key_synchronization_callback is not None and active_key_synchronization_callback_domainFilter is not None:
            self._active_key_synchronization_df = DomainMatcherList(active_key_synchronization_callback_domainFilter)
        else:
            self._active_key_synchronization_df = None

    def setDomainEcryptionType(self, domain_or_keyId: Union[str, int], type: int = 1) -> None:
        self._encryption_type[domain_or_keyId] = type
        # 0 = not encrypted
        # 1 = encrypted
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

    async def requestKDC(self, domain_or_keyId: Union[str, int, List[Union[str, int]]]):

        if not isinstance(domain_or_keyId, list):
            domain_or_keyId = [domain_or_keyId]

        out = []

        if self._active_key_synchronization_df is not None and self.active_key_synchronization_callback is not None:
            c = []
            r = []
            for d_or_id in domain_or_keyId:
                if not isinstance(domain_or_keyId, str):
                    if 'int' not in self._active_key_synchronization_df.literal:
                        r.append(d_or_id)
                    else:
                        c.append(d_or_id)
                else:
                    if not self._active_key_synchronization_df.match_any(domain_or_keyId):
                        r.append(d_or_id)
                    else:
                        c.append(d_or_id)

            if c:
                if self.active_key_synchronization_callback_is_async:
                    a = await self.active_key_synchronization_callback(c) # type: ignore
                else:
                    a = self.active_key_synchronization_callback(c)
                if not isinstance(a, list):
                    raise Exception('active_key_synchronization_callback must return list')
                out.extend(a) # type: ignore
            if r:
                res = await self._requestKDC(r)
                out.extend(res)
        else:
            rs = await self._requestKDC(domain_or_keyId)
            out.extend(rs)
        

        for (keyId, domain, key) in out:
            keyId = tuple(keyId) if isinstance(keyId, (tuple, list)) else (0, keyId)
            self._x_domain_keyId[domain] = keyId
            self._x_keyId_key[keyId] = key
            print(f'KDC: Добавлены ключи domain: {domain}, keyId: {keyId}')

    async def _requestKDC(self, domain_or_keyId: List[Union[str, int]]):
        print(f'RAW: start kdc request to [{domain_or_keyId}]')
        rs = await self._client.request(GNRequest('GET', Url(f'gn://{self._kdc_domain}/api/sys/server/keys'),
                                                payload=domain_or_keyId), keep_alive=self._active_key_synchronization)
        print('RAW: END kdc request')

        if not rs.command.ok:
            print(f'ERROR: {rs.command} {rs.payload}')
            raise rs
        
        if not isinstance(rs.payload, list):
            print(f'command.value -> {rs.command.value}. ok: {bool(rs.command.ok)}, app: {bool(rs.command.app)}, cors: {bool(rs.command.cors)}, dns: {bool(rs.command.dns)}, dns.DomainBlocked: {bool(rs.command.dns.DomainBlocked)}, Forbidden: {bool(rs.command.Forbidden)}, app.Forbidden: {bool(rs.command.app.Forbidden)}')
            raise Exception(f'r.payload is not list. {type(rs.payload)} -> {rs.payload}')

        return rs.payload

    def getKey(self, domain_or_keyId: Union[str, Tuple[int, int]]) -> bytes:
        if isinstance(domain_or_keyId, str):
            return self._x_keyId_key[self._x_domain_keyId[domain_or_keyId]]
        else:
            return self._x_keyId_key.get(domain_or_keyId) # type: ignore

    def getDomainById(self, keyId: int) -> Optional[str]:
        for d, k in self._x_domain_keyId.items():
            if k == keyId:
                return d
        return None
    
    def getKeyIdByDomain(self, domain: str) -> Optional[int]:
        return self._x_domain_keyId.get(domain) # type: ignore

    async def requestKeyIfNotExist(self, domain_or_keyId: Union[List[Union[str, int]], str, int]):
        if isinstance(domain_or_keyId, str):
            if domain_or_keyId not in self._x_domain_keyId:
                await self.requestKDC(domain_or_keyId)
        else:
            if domain_or_keyId not in self._x_keyId_key:
                await self.requestKDC(domain_or_keyId)
    
    def deleteKeyByDomain(self, domain: str) -> None:
        keyid = self._x_domain_keyId.pop(domain, None)

        if keyid is None:
            return
        
        self._x_keyId_key.pop(keyid)






