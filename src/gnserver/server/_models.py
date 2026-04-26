
import inspect
from typing import Callable, Awaitable

from gnobjects.net.tools import DomainMatcherList, DomainMatcherDict

_DEP_DEFAULT_ALL: dict[str, int] = {
    "*~*.origin.shield.gn": 2,
    "[::1]**": 0,
    "**": 1,
}

_DEP_DEFAULT_SPECIFIC: dict[str, int] = {
    "*~*.origin.shield.gn": 2,
    "[::1]**": 0,
}

class DEPConfig:
    def __init__(self,
                 kdc_active_key_synchronization_domain_filter: list[str] | None = None,
                 allow_kdc_active_key_synchronization: bool = True,
                 kdc_allowed_domains: list[str] | None = None,
                 kdc_allowed_domains_callback: Callable[[str], bool | Awaitable[bool]] | None = None,
                 established_encryption_types_for_domain: int | dict[str, int] | Callable[[str], int | None | Awaitable[int | None]] | None = None,
                 start_kdc_requested_domains: list[str] | None = None,
                 allow_unencrypted_connections: bool = False,
                 allow_local_unencrypted_connections: bool = True,
                 start_kdc_passive_keys: list[tuple[tuple[int, int], str, bytes]] | None = None,
                 kdc_active_key_synchronization_callback: Callable[
                                                                    [list[str | tuple[int, int]]],
                                                                    list[tuple[tuple[int, int], str, bytes] | bool]
                                                                    | Awaitable[list[tuple[tuple[int, int], str, bytes] | bool]]
                                                                ] | None = None,
                 kdc_active_key_synchronization_callback_domain_filter: list[str] | None = None,
                 incoming_datagram_workers: int = 1,
                 incoming_datagram_queue_size: int = 8192,
                 incoming_datagram_global_lock: bool = False,
                 max_inactive_transport_sessions: int = 8192,
                 ) -> None:
        """
        # Datagram Encryption Protocol Config


        :kdc_active_key_synchronization_domain_filter: Фильтр доменов допущенных к активной синхронизации. Поддерживает *, **
        :allow_kdc_active_key_synchronization: Активная синхронизация ключей с установленым KDC. Если с сервером было установлено новое соеденение, ключи к корому не были найдены, они будут запрошены у сервера KDC
        :kdc_allowed_domains: Фильтр доменов, для которых вообще разрешен bootstrap через KDC. По умолчанию `None` = KDC разрешен для всех доменов.
        :kdc_allowed_domains_callback: Дополнительная sync/async policy-проверка домена для bootstrap через KDC. Если возвращает False, bootstrap через KDC запрещен.
        :established_encryption_types_for_domain: Политика типа шифрования для доменов с уже установленными ключами.
            `None` = использовать дефолтную политику,
            `int` = тип шифрования для всех доменов (специфичные дефолты имеют приоритет),
            `dict[str, int]` = паттерн домена → тип шифрования (мёрджится с дефолтами, пользовательские записи имеют приоритет),
            `Callable[[str], int | None]` = пользовательская sync/async функция (специфичные дефолты имеют приоритет).
            Дефолт: `{"*~*.origin.shield.gn": 2, "[::1]**": 0, "**": 1}`
        :start_kdc_requested_domains: Домены, ключи для которых будут запрошену у KDC при старте сервера

        :allow_unencrypted_connections: Разрешать незашифрованные соединения
        :allow_local_unencrypted_connections: Разрешать незашифрованные локальные соединения
        :start_kdc_passive_keys: Ключи, которые при старте сервера будут добавлены. Формат ключа `tuple[tuple[key_group-int:100...255, key_id-int:8B], domain-str, key-bytes:64B]`

        :kdc_active_key_synchronization_callback: callback для установки ключей самостоятельно. Если return False, то синхронизация будет отключена. Если return True, то будет предпринята попытка синхронизации через KDC.
        :kdc_active_key_synchronization_callback_domainFilter: фильтр допуска к callback-у. Поддерживает *, **,  int - для всех keyId

        :incoming_datagram_workers: количество фиксированных workers для входящих UDP датаграмм
        :incoming_datagram_queue_size: max размер очереди на worker для входящих UDP датаграмм
        :incoming_datagram_global_lock: если True, все входящие датаграммы обрабатываются строго последовательно через глобальный lock
        :max_inactive_transport_sessions: max количество неактивных pre-QUIC/PQ transport-сессий, которые сохраняются после разрыва QUIC для resume без повторного PQ handshake

        """
        self.kdc_active_key_synchronization_domain_filter = kdc_active_key_synchronization_domain_filter
        self.allow_kdc_active_key_synchronization = allow_kdc_active_key_synchronization
        self.kdc_allowed_domains = list(kdc_allowed_domains) if kdc_allowed_domains is not None else None
        self.kdc_allowed_domains_callback = kdc_allowed_domains_callback
        self.start_kdc_requested_domains = list(start_kdc_requested_domains or [])
        self.allow_unencrypted_connections = allow_unencrypted_connections
        self.allow_local_unencrypted_connections = allow_local_unencrypted_connections
        self.start_kdc_passive_keys = start_kdc_passive_keys
        self.kdc_active_key_synchronization_callback = kdc_active_key_synchronization_callback
        self.kdc_active_key_synchronization_callback_domain_filter = kdc_active_key_synchronization_callback_domain_filter
        self.incoming_datagram_workers = max(1, int(incoming_datagram_workers or 1))
        self.incoming_datagram_queue_size = max(1, int(incoming_datagram_queue_size or 1))
        self.incoming_datagram_global_lock = bool(incoming_datagram_global_lock)
        self.max_inactive_transport_sessions = max(1, int(max_inactive_transport_sessions or 1))

        self._kdc_allowed_domains_matcher = DomainMatcherList(self.kdc_allowed_domains) if self.kdc_allowed_domains is not None else None

        policy = established_encryption_types_for_domain
        if isinstance(policy, bool):
            raise TypeError('established_encryption_types_for_domain cannot be bool')
        if policy is None or isinstance(policy, dict):
            merged: dict[str, int] = dict(policy) if policy is not None else {}
            for k, v in _DEP_DEFAULT_ALL.items():
                if k not in merged:
                    merged[k] = v
            self.established_encryption_types_for_domain: int | dict[str, int] | Callable = merged
            self._established_matcher = DomainMatcherDict(merged)
            self._established_callable_is_async = False
        elif isinstance(policy, int):
            self.established_encryption_types_for_domain = policy
            self._established_matcher = DomainMatcherDict(_DEP_DEFAULT_SPECIFIC)
            self._established_callable_is_async = False
        elif callable(policy):
            self.established_encryption_types_for_domain = policy
            self._established_matcher = DomainMatcherDict(_DEP_DEFAULT_SPECIFIC)
            self._established_callable_is_async = inspect.iscoroutinefunction(policy)
        else:
            raise TypeError('established_encryption_types_for_domain must be int, dict[str, int], Callable[[str], int | None], or None')

    async def isKDCAllowedForDomain(self, domain: str) -> bool:
        allowed = True

        if self._kdc_allowed_domains_matcher is not None:
            allowed = self._kdc_allowed_domains_matcher.match_any(domain)

        if allowed and self.kdc_allowed_domains_callback is not None:
            callback_result = self.kdc_allowed_domains_callback(domain)
            if inspect.isawaitable(callback_result):
                callback_result = await callback_result
            allowed = bool(callback_result)

        return allowed

    async def getEstablishedEncryptionTypeForDomain(self, domain: str) -> int | None:
        policy = self.established_encryption_types_for_domain

        if isinstance(policy, dict):
            return self._established_matcher.match(domain)

        specific = self._established_matcher.match(domain)
        if specific is not None:
            return specific

        if isinstance(policy, int):
            return policy

        result = policy(domain)
        if self._established_callable_is_async:
            result = await result
        return result
