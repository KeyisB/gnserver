
from typing import Optional, List, Callable, Union, Tuple, Coroutine


class DEPConfig:
    def __init__(self,
                 kdc_active_key_synchronization_domain_filter: Optional[List[str]] = None,
                 allow_kdc_active_key_synchronization: bool = True,
                 start_kdc_requested_domains: List[str] = [],
                 allow_unencrypted_connections: bool = False,
                 allow_local_unencrypted_connections: bool = True,
                 start_kdc_passive_keys: Optional[List[Tuple[Tuple[int, int], str, bytes]]] = None,
                 kdc_active_key_synchronization_callback: Optional[Callable[[List[Union[str, int]]], Union[List[Tuple[int, str, bytes]], Coroutine]]] = None,
                 kdc_active_key_synchronization_callback_domain_filter: Optional[List[str]] = None
                 ) -> None:
        """
        # Datagram Encryption Protocol Config


        :kdc_active_key_synchronization_domain_filter: Фильтр доменов допущенных к активной синхронизации. Поддерживает *, **
        :allow_kdc_active_key_synchronization: Активная синхронизация ключей с установленым KDC. Если с сервером было установлено новое соеденение, ключи к корому не были найдены, они будут запрошены у сервера KDC
        :start_kdc_requested_domains: Домены, ключи для которых будут запрошену у KDC при старте сервера
        
        :allow_unencrypted_connections: Разрешать незашифрованные соединения
        :allow_local_unencrypted_connections: Разрешать незашифрованные локальные соединения
        :start_kdc_passive_keys: Ключи, которые при старте сервера будут добавлены. Формат ключа `Tuple[Tuple[key_group-int:100...255, key_id-int:8B], domain-str, key-bytes:64B]`

        :kdc_active_key_synchronization_callback: callback для установки ключей самостоятельно
        :kdc_active_key_synchronization_callback_domainFilter: фильтр допуска к callback-у. Поддерживает *, **,  int - для всех keyId

        """
        self.kdc_active_key_synchronization_domain_filter = kdc_active_key_synchronization_domain_filter
        self.allow_kdc_active_key_synchronization = allow_kdc_active_key_synchronization
        self.start_kdc_requested_domains = start_kdc_requested_domains
        self.allow_unencrypted_connections = allow_unencrypted_connections
        self.allow_local_unencrypted_connections = allow_local_unencrypted_connections
        self.start_kdc_passive_keys = start_kdc_passive_keys
        self.kdc_active_key_synchronization_callback = kdc_active_key_synchronization_callback
        self.kdc_active_key_synchronization_callback_domain_filter = kdc_active_key_synchronization_callback_domain_filter
  



