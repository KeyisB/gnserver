
import os
import sys
import time
import socket
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from typing import Optional, Callable, Union, cast, List, Any, Dict
from .._kdc_object import KDCObject
from aioquic.asyncio.server import QuicServer
from aioquic.quic.connection import QuicConnection
from asyncio import Queue
from aioquic.quic.packet import pull_quic_header
from aioquic.buffer import Buffer
import asyncio
from typing import Optional, Callable, Tuple
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.connection import QuicConnection

from gnobjects.net.objects import Url
from gnobjects.net.tools import DomainMatcherList
from gnobjects.net.domains import GNDomain

from ._models import DEPConfig

NEW_SIZE = 1191
import aioquic.quic.configuration as cfg
cfg.SMALLEST_MAX_DATAGRAM_SIZE = NEW_SIZE
targets = [
    "aioquic.quic.configuration",
    "aioquic.asyncio.server",
    "aioquic.quic.connection",
    "aioquic.quic.packet"
]

for name in targets:
    m = sys.modules.get(name)
    if not m:
        continue
    if "SMALLEST_MAX_DATAGRAM_SIZE" in m.__dict__:
        m.__dict__["SMALLEST_MAX_DATAGRAM_SIZE"] = NEW_SIZE



def is_quic_initial(b0: int) -> bool:
    return (b0 & 0xF0) == 0xC0


class ConnectionEncryptor:
    def __init__(self, eEndpoint: 'DatagramEndpoint'):
        self.counter = 0 # 8B
        self.eEndpoint = eEndpoint

        self.ready: Union[None, bool] = False
        self.not_ready_queue = Queue()

        self.encryption_type: int = 0
        self.keyid: Optional[int] = 0

        

    async def initByKeyid(self, encryption_type: int, keyid: Tuple[int, int]) -> str:
        self.encryption_type = encryption_type
        await self.eEndpoint._kdc.requestKeyIfNotExist(keyid)

        key = self.eEndpoint._kdc.getKey(keyid)
        
        DestDomain = self.eEndpoint._kdc.getDomainById(keyid)

        if DestDomain is None:
            print('ERROR: 143.822')
            raise Exception('ERROR: 143.822')
        
        self_domain = self.eEndpoint._kdc._client._domain
        
        
        
        self._key_in = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=DestDomain.encode() + self_domain.encode(), info=b'gn:DgEncryptor').derive(key)
        self._key_out = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=self_domain.encode() + DestDomain.encode(), info=b'gn:DgEncryptor').derive(key)

        self.ready = True
        return DestDomain

    async def initRaw(self):
        self.ready = True

    
    async def initByDomain(self, encryption_type: int, domain: str) -> int:

        self.encryption_type = encryption_type
        if encryption_type == 0:
            await self.initRaw()
            return 0

        await self.eEndpoint._kdc.requestKeyIfNotExist(domain)

        self.keyid = self.eEndpoint._kdc.getKeyIdByDomain(domain)

        if self.keyid is None:
            self.keyid = 0
            print('ERROR: 143.823')
            raise Exception('ERROR: 143.823')
        
        key = self.eEndpoint._kdc.getKey(self.keyid)

        self_domain = self.eEndpoint._kdc._client._domain
        
        self._key_in = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=domain.encode() + self_domain.encode(), info=b'gn:DgEncryptor').derive(key)
        self._key_out = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=self_domain.encode() + domain.encode(), info=b'gn:DgEncryptor').derive(key)

        self.ready = True
        return self.keyid


    def _make_nonce(self) -> bytes: # 15B
        now = int(time.time()) & 0xFFFFFFFFFF
        self.counter = (self.counter + 1) & 0xFFFFFFFFFFFFFFFF
        return now.to_bytes(5, "big") + self.counter.to_bytes(8, "big") + os.urandom(2)
    
    def encrypt(self, packet: bytes) -> bytes:
        nonce = self._make_nonce()
        cipher = AES.new(self._key_out, AES.MODE_OCB, nonce=nonce, mac_len=16)
        ciphertext, tag = cipher.encrypt_and_digest(packet)
        return nonce + ciphertext + tag

    def decrypt(self, packet: bytes) -> bytes:
        if len(packet) < 15 + 16:
            raise ValueError("Packet too short")
        nonce = packet[:15]
        tag = packet[-16:]
        ciphertext = packet[15:-16]
        cipher = AES.new(self._key_in, AES.MODE_OCB, nonce=nonce, mac_len=16)
        return cipher.decrypt_and_verify(ciphertext, tag)




class QuicProtocolShell(QuicConnectionProtocol):
    def __init__(
        self,
        quic: QuicConnection,
        datagramEndpoint: 'DatagramEndpoint',
        client: bool,
        stream_handler: Optional[
            Callable[[asyncio.StreamReader, asyncio.StreamWriter], None]
        ] = None,
    ) -> None:
        super().__init__(quic=quic, stream_handler=stream_handler)
        self.datagramEndpoint = datagramEndpoint
        self._client = client
        self._quic._max_datagram_size = 110 # error
        self._gn_protocol_version = 0 # max 127 # 7b # encoding and encryption info

    def setDatagramEndpoint(self, datagramEndpoint: 'DatagramEndpoint'):
        self.datagramEndpoint = datagramEndpoint

        self._upd_datagram_size = (
            1200 # quic init
            + 32
            - 1 # version + type
            - (31 if datagramEndpoint._default_encryption_type != 0 else 0) # encryption data
            )

        if self._client:
            self._quic._max_datagram_size = self._upd_datagram_size - 9 # first packet
        else:
            self._quic._max_datagram_size = self._upd_datagram_size

    def setDefault_max_datagram_size(self):
        self._quic._max_datagram_size = self._upd_datagram_size


    def callback_domain(self, domain: Optional[str]): ...

class TransportProxy(asyncio.DatagramTransport):
    def __init__(self, base: List[asyncio.DatagramTransport], endpoint: 'DatagramEndpoint'):
        self.base6 = None
        self.base4 = None

        for t in base:
            sock = t.get_extra_info("socket")
            if not sock:
                continue

            fam = sock.family

            if fam == socket.AF_INET:
                self.base4 = t

            elif fam == socket.AF_INET6:
                # Проверяем: dual-stack или чистый v6
                try:
                    ip = sock.getsockname()[0]
                    if ip.startswith("::ffff:"):
                        # IPv4-mapped IPv6 → считаем как v4
                        self.base4 = t
                    else:
                        self.base6 = t
                except Exception:
                    self.base6 = t

        if not self.base4 and not self.base6:
            raise RuntimeError("No usable DatagramTransport (IPv4/IPv6) found")

        # fallback: если есть только один транспорт
        if not self.base4:
            self.base4 = self.base6
        if not self.base6:
            self.base6 = self.base4

        self.endpoint = endpoint
        self.tablex_maddr_isV4 = set()

    def sendto(self, data: bytes, addr=None):
        self.endpoint.sendto(data, addr)
        


    def sendMapped(self, data: bytes, addr=None):
        maddr = DatagramEndpoint.from_addr_to_maddr(addr)
        if maddr in self.tablex_maddr_isV4:
            self.base4.sendto(data, addr)
        else:
            self.base6.sendto(data, addr)
    

    def addV4maddr(self, maddr):
        if maddr not in self.tablex_maddr_isV4:
            self.tablex_maddr_isV4.add(maddr)

    def __getattr__(self, item):
        t = getattr(self, "base6", None) or getattr(self, "base4", None)
        return getattr(t, item)


class DatagramEndpoint(asyncio.DatagramProtocol):
    def __init__(self, quic_routing: Union[QuicServer, QuicProtocolShell], kdc: KDCObject, transports: int = 1, dEPConfig: Optional[DEPConfig] = None) -> None:
        self._quic_routing = quic_routing
        self._kdc = kdc
        self.loop = self._quic_routing._loop

        self._gn_protocol_version = 0 # max 127 # 7b # encoding and ecryption info
        self._default_encryption_type = 1
        self._upd_datagram_size = 1200

        self.x_maddr_dgEnc = {} # (ipv6, port, scopeid): DatagramEncryptor


        self._domain: Optional[str] = None


        self.__transports = transports
        self.__transports_list = []

        self.x_cid_domain = {}


        if dEPConfig is None:
            dEPConfig = DEPConfig()

        self.DEPConfig: DEPConfig = dEPConfig

        self.active_key_synchronization_callback_domain_filter = None
        if dEPConfig is not None:
            a = dEPConfig.kdc_active_key_synchronization_domain_filter
            if a is not None:
                self.active_key_synchronization_callback_domain_filter = DomainMatcherList(a)
                del a
    
    def add_QuicProtocolShellServer_domain(self, data: bytes, domain: str):
        h = pull_quic_header(Buffer(data=data))
        self.x_cid_domain[h.destination_cid] = domain

    def getDomain(self, proto: QuicProtocolShell) -> Optional[str]:
        d = self.x_cid_domain.get(proto._quic.original_destination_connection_id, None)
        if d is None:
            return
        return d
    
    
    def connection_lost(self, exc):
        self._quic_routing.connection_lost(exc)

    def error_received(self, exc):
        if hasattr(self._quic_routing, "error_received"):
            self._quic_routing.error_received(exc)

    def connection_made(self, transport):
        self.raw_transport = transport

        self.__transports_list.append(transport)

        if len(self.__transports_list) == self.__transports:
            self.connection_made_all()

    def connection_made_all(self):
        proxy = TransportProxy(self.__transports_list, self)

        self._quic_routing.connection_made(proxy)

        self.transport = proxy

    def getDgEnc(self, addr: Any) -> ConnectionEncryptor:
        r = self.x_maddr_dgEnc.get(addr)

        if r is not None: # было соеденение
            return r
        
        r = ConnectionEncryptor(self)
        self.x_maddr_dgEnc[addr] = r

        return r
    
    

    def datagram_received(self, data, addr):
        self.loop.create_task(self._handle_datagram(data, addr))

    @staticmethod
    def from_addr_to_maddr(addr) -> Tuple[str, int, int]:
        if len(addr) == 2:
            if addr[0] == '127.0.0.1':
                return ("::1", addr[1], 0)
            return ('::ffff:' + addr[0], addr[1], 0)
        elif len(addr) == 3:
            return addr
        else: # len == 4
            return (addr[0], addr[1], addr[3])

    def construct_initial(self, encryption_type: int, keyId: int) -> bytes:
        data = bytearray()

        b0 = ((self._gn_protocol_version & 0x7F) << 1) | (True & 0x01)
        data.append(b0)

        if isinstance(keyId, tuple):
            keyType = keyId[0]
            keyId = keyId[1]
        else:
            keyType = 0
            

        if keyId < 0:
            keyId = abs(keyId)


        b1 = ((0 & 0x0F) << 4) | (encryption_type & 0x0F) # command 4b | encryption_type 4b
        data.append(b1)

        data.extend(int(keyType).to_bytes(1, 'big')) # keyType # 1B # 0 - 255
        data.extend(keyId.to_bytes(7, 'big')) # keyId # 7B

        return bytes(data)

    def sendto(self, data: bytes, addr):
        
        
        maddr = self.from_addr_to_maddr(addr)

        connectionEnc = self.getDgEnc(maddr)

        if is_quic_initial(data[0]): # init соеденения

            if self._domain is None:
                print('Server init with None domain. It`s client')
            else:
                self.loop.create_task(self.async_sendto(connectionEnc, data, addr))
                return

        if not connectionEnc.ready:
            connectionEnc.not_ready_queue.put_nowait((data, addr))
            return
        

        b0 = bytes([((self._gn_protocol_version & 0x7F) << 1) | (False & 0x01)])

        if connectionEnc.encryption_type != 0:
            try:
                enc = connectionEnc.encrypt(data)
            except Exception:
                print("GN Prequic: UPD Decryption error")
                return
        else:
            enc = data

        self.transport.sendMapped(b0 + enc, addr)

    async def async_sendto(self, connectionEnc: 'ConnectionEncryptor', data: bytes, addr):
        if not connectionEnc.ready:
            keyid = await connectionEnc.initByDomain(self._default_encryption_type, cast(str, self._domain))
        else:
            keyid = connectionEnc.keyid

        p = self.construct_initial(self._default_encryption_type, keyid)

        if self._default_encryption_type != 0:
            try:
                enc = connectionEnc.encrypt(data)
            except Exception:
                print("GN Prequic: UPD Encryption error")
                return
        else:
            enc = data
        
        dg = p + enc
        
        self.transport.sendMapped(dg, addr)


        if not connectionEnc.not_ready_queue.empty():
            while not connectionEnc.not_ready_queue.empty():
                data, addr = connectionEnc.not_ready_queue.get_nowait()
                self.sendto(data, addr)
        

    async def _handle_datagram(self, data: bytes, addr):
        
        value = (data[0] >> 1) & 0x7F
        if value != self._gn_protocol_version:
            print(f"GN Prequic: UPD Version mismatch {value} != {self._gn_protocol_version}")
            return
        
        maddr = self.from_addr_to_maddr(addr)


        connectionEnc  = self.getDgEnc(maddr)
        if connectionEnc.ready is None:
            print(f'UDP: datagramm blocked ({maddr})')

        d = None

        if data[0] & 0x01: # если системный пакет.
            commnd_id = (data[1] >> 4) & 0x0F
            datagram = data[10:]
            if commnd_id == 0 and not connectionEnc.ready: # initial
                

                if len(addr) == 2:
                    self.transport.addV4maddr(maddr)

                encryption_type = data[1] & 0x0F
                if encryption_type != 0: # encrypted
                    
                        
                    keyType = data[2]
                    key_id = int.from_bytes(data[3:10], 'big')

                    
                    if not self._kdc._active_key_synchronization:
                        key = self._kdc.getKey((keyType, key_id))
                        if key is None:
                            connectionEnc.ready = None # block
                            raise Exception('Соединение отклонено из за политики kdc_active_key_synchronization')

                    d = await connectionEnc.initByKeyid(encryption_type, (keyType, key_id))
                    if self.active_key_synchronization_callback_domain_filter is not None and not self.active_key_synchronization_callback_domain_filter.match_any(d) and not GNDomain.isCore(d):
                        connectionEnc.ready = None
                        raise Exception(f'Соединение {d} отклонено из за политики active_key_synchronization_callback_domain_filter: {self.DEPConfig.kdc_active_key_synchronization_domain_filter}')

                else:
                    if maddr[0] in ('::1', '127.0.0.1', '::ffff:127.0.0.1'):
                        if not self.DEPConfig.allow_local_unencrypted_connections:
                            connectionEnc.ready = None
                            raise Exception('Соединение отклонено из за политики DEPConfig.allow_local_unencrypted_connections')
                    else:
                        if not self.DEPConfig.allow_unencrypted_connections:
                            connectionEnc.ready = None
                            raise Exception('Соединение отклонено из за политики DEPConfig.allow_unencrypted_connections')
                        



                    await connectionEnc.initRaw()
                    d = Url.ip_and_port_to_ipv6_with_port(maddr[0], maddr[1])

                while not connectionEnc.not_ready_queue.empty():
                    raw, a = connectionEnc.not_ready_queue.get_nowait()
                    await self._handle_datagram(raw, a)
        else:
            datagram = data[1:]

            if not connectionEnc.ready:
                print('IN QUEUE')
                connectionEnc.not_ready_queue.put_nowait((data, addr))
                return

        if connectionEnc.encryption_type != 0:
            try:
                dec = connectionEnc.decrypt(datagram)
                
            except Exception as e:
                print(f"UDP: UPD Decryption error: {e}")
                print(f'info:\naddr: {addr}\n')
                return
        else:
            dec = datagram

        if d is not None and isinstance(self._quic_routing, QuicServer):
            self.add_QuicProtocolShellServer_domain(dec, d)

        self._quic_routing.datagram_received(dec, addr)


print(' '* 25 + f'PID: {os.getpid()}')