
import os
import sys
import time
import socket
import math
from collections import deque
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from typing import Optional, Callable, Union, cast, List, Any, Deque, Dict
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
from gnobjects.net.fastcommands import AllGNFastCommands
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
        self.domain: Optional[str] = None
        self.processing_lock = asyncio.Lock()
        self.key_fetching = False

        

    async def initByKeyid(self, encryption_type: int, keyid: Tuple[int, int]) -> str:
        self.encryption_type = encryption_type
        await self.eEndpoint._kdc.requestKeyIfNotExist(keyid)

        key = self.eEndpoint._kdc.getKey(keyid)
        
        DestDomain = self.eEndpoint._kdc.getDomainById(cast(Any, keyid))

        if DestDomain is None:
            raise AllGNFastCommands.transport.KeyDomainNotFound({'keyid': keyid})
        
        self_domain = self.eEndpoint._kdc._client._domain
        
        
        
        self._key_in = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=DestDomain.encode() + self_domain.encode(), info=b'gn:DgEncryptor').derive(key)
        self._key_out = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=self_domain.encode() + DestDomain.encode(), info=b'gn:DgEncryptor').derive(key)

        self.ready = True
        self.domain = DestDomain
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
            raise AllGNFastCommands.transport.KeyIdNotFound({'domain': domain})
        
        key = self.eEndpoint._kdc.getKey(self.keyid) # type: ignore

        self_domain = self.eEndpoint._kdc._client._domain
        
        self._key_in = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=domain.encode() + self_domain.encode(), info=b'gn:DgEncryptor').derive(key)
        self._key_out = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=self_domain.encode() + domain.encode(), info=b'gn:DgEncryptor').derive(key)

        self.ready = True
        self.domain = domain
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

        self._inbound_workers = max(1, int(getattr(self.DEPConfig, 'incoming_datagram_workers', 1)))
        self._inbound_queue_size = max(1, int(getattr(self.DEPConfig, 'incoming_datagram_queue_size', 8192)))
        self._inbound_global_lock_enabled = bool(getattr(self.DEPConfig, 'incoming_datagram_global_lock', False))
        self._inbound_queues: List[Queue] = [Queue(maxsize=self._inbound_queue_size) for _ in range(self._inbound_workers)]
        self._inbound_tasks: List[asyncio.Task] = []
        self._inbound_started = False
        self._inbound_drop_count = 0
        self._inbound_global_lock = asyncio.Lock()

        # Sliding 5s UDP ingress telemetry used by App load score.
        self._load_window_seconds = 5.0
        self._load_accept_events: Deque[float] = deque()
        self._load_drop_events: Deque[float] = deque()
        self._load_queue_wait_ms_events: Deque[Tuple[float, float]] = deque()

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

    def dropProtocolState(self, proto: QuicProtocolShell):
        self.x_cid_domain.pop(proto._quic.original_destination_connection_id, None)

    async def _fetch_key_and_resume(self, connectionEnc: ConnectionEncryptor, encryption_type: int, keyid: Tuple[int, int]):
        try:
            await self._kdc.requestKeyIfNotExist(keyid)

            if self._inbound_global_lock_enabled:
                async with self._inbound_global_lock:
                    await self._finalize_key_and_flush(connectionEnc, encryption_type, keyid)
            else:
                async with connectionEnc.processing_lock:
                    await self._finalize_key_and_flush(connectionEnc, encryption_type, keyid)
        except Exception as e:
            connectionEnc.ready = None
            print(f'UDP key fetch error: {e}')
        finally:
            connectionEnc.key_fetching = False

    async def _finalize_key_and_flush(self, connectionEnc: ConnectionEncryptor, encryption_type: int, keyid: Tuple[int, int]):
        d = await connectionEnc.initByKeyid(encryption_type, keyid)
        if self.active_key_synchronization_callback_domain_filter is not None and not self.active_key_synchronization_callback_domain_filter.match_any(d) and not GNDomain.isCore(d):
            connectionEnc.ready = None
            raise AllGNFastCommands.transport.PolicyDenied({
                'domain': d,
                'policy': 'active_key_synchronization_callback_domain_filter',
                'filter': self.DEPConfig.kdc_active_key_synchronization_domain_filter,
            })

        # process queued datagrams for this peer after key becomes ready
        while not connectionEnc.not_ready_queue.empty():
            raw, a = connectionEnc.not_ready_queue.get_nowait()
            await self._handle_datagram(raw, a)

    async def _inbound_worker(self, worker_id: int, queue: Queue):
        while True:
            try:
                item = await queue.get()
            except asyncio.CancelledError:
                break

            try:
                if len(item) == 3:
                    data, addr, enqueued_at = item
                else:
                    data, addr = item
                    enqueued_at = time.monotonic()

                wait_ms = max(0.0, (time.monotonic() - float(enqueued_at)) * 1000.0)
                self._record_queue_wait_ms(wait_ms)

                maddr = self.from_addr_to_maddr(addr)
                connectionEnc = self.getDgEnc(maddr)

                if self._inbound_global_lock_enabled:
                    async with self._inbound_global_lock:
                        await self._handle_datagram(data, addr)
                else:
                    # Prevent concurrent processing for the same peer even with multiple workers.
                    async with connectionEnc.processing_lock:
                        await self._handle_datagram(data, addr)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f'UDP worker[{worker_id}] error: {e}')
            finally:
                queue.task_done()

    def _start_inbound_workers(self):
        if self._inbound_started:
            return

        self._inbound_started = True
        self._inbound_tasks = []
        for worker_id, queue in enumerate(self._inbound_queues):
            task = self.loop.create_task(self._inbound_worker(worker_id, queue))
            self._inbound_tasks.append(task)

    def _stop_inbound_workers(self):
        for task in self._inbound_tasks:
            task.cancel()
        self._inbound_tasks.clear()
        self._inbound_started = False

        # purge queued datagrams on shutdown to release memory immediately
        for queue in self._inbound_queues:
            while True:
                try:
                    queue.get_nowait()
                    queue.task_done()
                except asyncio.QueueEmpty:
                    break

    def _inbound_shard(self, addr) -> int:
        if self._inbound_workers == 1:
            return 0
        maddr = self.from_addr_to_maddr(addr)
        return hash(maddr) % self._inbound_workers

    def _prune_load_window(self, now: Optional[float] = None):
        if now is None:
            now = time.monotonic()

        threshold = now - self._load_window_seconds

        while self._load_accept_events and self._load_accept_events[0] < threshold:
            self._load_accept_events.popleft()

        while self._load_drop_events and self._load_drop_events[0] < threshold:
            self._load_drop_events.popleft()

        while self._load_queue_wait_ms_events and self._load_queue_wait_ms_events[0][0] < threshold:
            self._load_queue_wait_ms_events.popleft()

    def _record_queue_wait_ms(self, wait_ms: float, now: Optional[float] = None):
        if now is None:
            now = time.monotonic()

        self._load_queue_wait_ms_events.append((now, wait_ms))
        self._prune_load_window(now)

    @staticmethod
    def _p95(values: List[float]) -> float:
        if not values:
            return 0.0

        ordered = sorted(values)
        idx = max(0, math.ceil(0.95 * len(ordered)) - 1)
        return float(ordered[idx])

    def getInboundLoadMetrics(self) -> Dict[str, float]:
        now = time.monotonic()
        self._prune_load_window(now)

        queue_capacity = max(1, self._inbound_workers * self._inbound_queue_size)
        queue_size = sum(queue.qsize() for queue in self._inbound_queues)
        queue_fill_ratio = min(1.0, queue_size / float(queue_capacity))

        dropped = len(self._load_drop_events)
        accepted = len(self._load_accept_events)
        total = dropped + accepted
        drop_rate = (dropped / total) if total > 0 else 0.0

        p95_udp_queue_wait_ms = self._p95([value for _, value in self._load_queue_wait_ms_events])

        return {
            'window_seconds': self._load_window_seconds,
            'queue_fill_ratio': queue_fill_ratio,
            # Name kept for compatibility with balancer formula naming.
            'drop_rate_10s': drop_rate,
            'p95_udp_queue_wait_ms': p95_udp_queue_wait_ms,
            'accepted_datagrams_window': float(accepted),
            'dropped_datagrams_window': float(dropped),
        }
    
    
    def connection_lost(self, exc):
        self._stop_inbound_workers()
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
        self._start_inbound_workers()

    def getDgEnc(self, addr: Any) -> ConnectionEncryptor:
        r = self.x_maddr_dgEnc.get(addr)

        if r is not None: # было соеденение
            return r
        
        r = ConnectionEncryptor(self)
        self.x_maddr_dgEnc[addr] = r

        return r
    
    

    def datagram_received(self, data, addr):
        if not self._inbound_started:
            self._start_inbound_workers()

        now = time.monotonic()
        self._prune_load_window(now)

        queue = self._inbound_queues[self._inbound_shard(addr)]
        try:
            queue.put_nowait((data, addr, now))
            self._load_accept_events.append(now)
        except asyncio.QueueFull:
            self._inbound_drop_count += 1
            self._load_drop_events.append(now)
            if self._inbound_drop_count == 1 or self._inbound_drop_count % 1024 == 0:
                print(
                    f'UDP inbound queue overflow: dropped={self._inbound_drop_count}, '
                    f'workers={self._inbound_workers}, queue_maxsize={self._inbound_queue_size}'
                )

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

        p = self.construct_initial(self._default_encryption_type, keyid) # type: ignore

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
            if commnd_id == 0: # initial
                if len(addr) == 2:
                    self.transport.addV4maddr(maddr)

                encryption_type = data[1] & 0x0F
                if not connectionEnc.ready:
                    if encryption_type != 0: # encrypted
                        keyType = data[2]
                        key_id = int.from_bytes(data[3:10], 'big')
                        keyid = (keyType, key_id)

                        if not self._kdc._active_key_synchronization:
                            key = self._kdc.getKey(keyid)
                            if key is None:
                                connectionEnc.ready = None # block
                                raise AllGNFastCommands.transport.PolicyDenied({
                                    'policy': 'kdc_active_key_synchronization',
                                    'keyid': keyid,
                                })

                        # if key is missing, fetch asynchronously to avoid blocking inbound workers
                        if self._kdc.getKey(keyid) is None:
                            connectionEnc.not_ready_queue.put_nowait((data, addr))
                            if not connectionEnc.key_fetching:
                                connectionEnc.key_fetching = True
                                self.loop.create_task(self._fetch_key_and_resume(connectionEnc, encryption_type, keyid))
                            return

                        d = await connectionEnc.initByKeyid(encryption_type, keyid)
                        if self.active_key_synchronization_callback_domain_filter is not None and not self.active_key_synchronization_callback_domain_filter.match_any(d) and not GNDomain.isCore(d):
                            connectionEnc.ready = None
                            raise AllGNFastCommands.transport.PolicyDenied({
                                'domain': d,
                                'policy': 'active_key_synchronization_callback_domain_filter',
                                'filter': self.DEPConfig.kdc_active_key_synchronization_domain_filter,
                            })

                    else:
                        if maddr[0] in ('::1', '127.0.0.1', '::ffff:127.0.0.1'):
                            if not self.DEPConfig.allow_local_unencrypted_connections:
                                connectionEnc.ready = None
                                raise AllGNFastCommands.transport.PolicyDenied({
                                    'policy': 'allow_local_unencrypted_connections',
                                    'addr': maddr,
                                })
                        else:
                            if not self.DEPConfig.allow_unencrypted_connections:
                                connectionEnc.ready = None
                                raise AllGNFastCommands.transport.PolicyDenied({
                                    'policy': 'allow_unencrypted_connections',
                                    'addr': maddr,
                                })

                        await connectionEnc.initRaw()
                        d = Url.ip_and_port_to_ipv6_with_port(maddr[0], maddr[1])
                        connectionEnc.domain = d

                    while not connectionEnc.not_ready_queue.empty():
                        raw, a = connectionEnc.not_ready_queue.get_nowait()
                        await self._handle_datagram(raw, a)
                else:
                    # Existing UDP association can still open new QUIC connections with new destination CID.
                    # Recompute domain on every initial packet so CID -> domain stays fresh.
                    if encryption_type != 0:
                        keyType = data[2]
                        key_id = int.from_bytes(data[3:10], 'big')
                        d = self._kdc.getDomainById(cast(Any, (keyType, key_id)))
                        if d is None:
                            d = connectionEnc.domain
                    else:
                        d = Url.ip_and_port_to_ipv6_with_port(maddr[0], maddr[1])

                    if d is not None:
                        connectionEnc.domain = d
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