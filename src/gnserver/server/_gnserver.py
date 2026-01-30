
import os
import sys
from typing import Optional, Union, Callable, cast
from pathlib import Path
from KeyisBTools.bytes.transformation import userFriendly, hash3
from KeyisBTools.models.serialization import deserialize
from KeyisBTools.cryptography import m1
from gnobjects.net.objects import Url

from ._app import App, GNRequest
from ._models import DEPConfig


class GNServer(App):
    def __init__(self, only_client: bool = False):
        """
        # GNServer
        """
        super().__init__(only_client=only_client)

        self.vmhostConfig: dict = {}
        self.fromHostConfig = self.vmhostConfig

        
        try:
            self._readFromHostConfig()
        except:
            pass


    @staticmethod
    def _normalize_gn_server_crt(gn_server_crt: Union[str, bytes, Path]) -> bytes:
        if isinstance(gn_server_crt, Path):
            gn_server_crt_data = open(gn_server_crt, 'rb').read()
        elif isinstance(gn_server_crt, str):
            if os.path.isfile(gn_server_crt):
                gn_server_crt_data = open(gn_server_crt, 'rb').read()
            else:
                gn_server_crt_data = userFriendly.decode(gn_server_crt)
        else:
            gn_server_crt_data = gn_server_crt
        return gn_server_crt_data


    @staticmethod
    def _get_gn_server_crt(gn_server_crt: Union[str, bytes, Path], domain: str) -> dict:
        gn_server_crt_data = GNServer._normalize_gn_server_crt(gn_server_crt)
        def _decode(data: bytes, domain: str, st=False):
            try:
                r = m1.fastDecrypt(data, hash3(domain.encode()))
                result = deserialize(r)
                return result
            except:
                if st:
                    raise Exception('Не удалось расшифровать gn_server_crt')
                else:
                    _ = gn_server_crt_data.decode() # type: ignore
                    _2 = userFriendly.decode(_)
                    return _decode(_2, domain, st=True)
        
        gn_server_crt_: dict = _decode(gn_server_crt_data, domain=domain) # type: ignore
        return gn_server_crt_


    def run( # type: ignore
        self,
        domain: str,
        port: int,
        gn_server_crt: Union[str, bytes, Path],
        *,
        host: str = '0.0.0.0',
        idle_timeout: float = 20.0,
        wait: bool = True,
        run: Optional[Callable] = None,
        dep_config: Optional[DEPConfig] = None
    ):
        
        self.domain = domain
        if dep_config is not None:
            self.setDEPConfig(dep_config)
        

        gn_server_crt_ = self._get_gn_server_crt(gn_server_crt, domain)

        self.client.setDomain(domain)
        self.client.init(gn_server_crt,
                         requested_domains=self.DEPConfig.start_kdc_requested_domains,
                         active_key_synchronization=self.DEPConfig.allow_kdc_active_key_synchronization,
                         active_key_synchronization_callback=self.DEPConfig.kdc_active_key_synchronization_callback,
                         active_key_synchronization_callback_domainFilter=self.DEPConfig.kdc_active_key_synchronization_callback_domain_filter
                         )


        @self.addEventListener('start', move_to_start=True) # type: ignore
        async def _on_start():
            await self.client._kdc.addServers(servers_keys=self.DEPConfig.start_kdc_passive_keys) # type: ignore


        if 'tls_certfile' in gn_server_crt_ and 'tls_keyfile' in gn_server_crt_:
            tls_certfile = gn_server_crt_['tls_certfile']
            tls_keyfile = gn_server_crt_['tls_keyfile']
        else:
            tls_certfile = None
            tls_keyfile = None



        return super().run(
            domain=domain,
            port=port,
            tls_certfile=tls_certfile, # type: ignore
            tls_keyfile=tls_keyfile, # type: ignore
            host=host,
            idle_timeout=idle_timeout,
            wait=wait,
            run=run
        )

    def runByVMHost(self,
        wait: bool = True
        ):
        """
        # Запусить через VM-host

        Запускает сервер через процесс vm-host
        """
        argv = sys.argv[1:]
        data_enc = argv[0]

        data: dict = deserialize(userFriendly.decode(data_enc)) # type: ignore


        if data['command'] == 'gn:vm-host:start':
            self.run(
                domain=data['domain'],
                port=data['port'],
                gn_server_crt=data.get('gn_server_crt'), # type: ignore
                host=data.get('host', '0.0.0.0'),

                wait=wait
            )

            @self.addEventListener('start')
            async def _ping():
                await self.client.request(GNRequest('post', Url(f'gn://[::1]:{data['!vmhost_port']}/s/starting-complete')))

    def _readFromHostConfig(self, data: Optional[dict] = None):
        if data is None:
            argv = sys.argv[1:]
            data_enc = argv[0]

            data = deserialize(userFriendly.decode(data_enc)) # type: ignore

        if not isinstance(data, dict):
            raise Exception('data is not dict')

        if 'vmhostConfig' in data:
            _vmhostConfig = data['vmhostConfig']
            if isinstance(_vmhostConfig, str) and os.path.isfile(_vmhostConfig):
                _vmhostConfig = open(_vmhostConfig, 'r').read()
                import json
                _vmhostConfig = cast(dict, json.loads(_vmhostConfig))
            
            if not isinstance(_vmhostConfig, dict):
                raise Exception('vmhostConfig is not dict')

            self.vmhostConfig.update(_vmhostConfig)
