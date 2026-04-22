
import os
import random
import sys
import time
import socket
import math
from collections import deque
import traceback
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
import hashlib
from typing import Optional, Callable, Tuple
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.connection import QuicConnection

from gnobjects.net.objects import Url
from gnobjects.net.fastcommands import AllGNFastCommands
from gnobjects.net.tools import DomainMatcherList
from gnobjects.net.domains import GNDomain

from .._gn_pq_session import derive_transport_keys_from_root64
from ._models import DEPConfig

import logging
logger = logging.getLogger("GNServer.DatagramEndpoint")

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


def _prequic_log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    logger.debug(f"[{stamp}] [GN PREQUIC] {message}")


def _format_cid(value: bytes) -> str:
    if not value:
        return "-"
    return value.hex()



def is_quic_initial(b0: int) -> bool:
    return (b0 & 0xF0) == 0xC0


def _derive_bootstrap_transport_keys(
    shared_key: bytes,
    *,
    local_domain: str,
    peer_domain: str,
) -> tuple[bytes, bytes]:
    key_in = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=peer_domain.encode() + local_domain.encode(),
        info=b'gn:DgEncryptor',
    ).derive(shared_key)
    key_out = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=local_domain.encode() + peer_domain.encode(),
        info=b'gn:DgEncryptor',
    ).derive(shared_key)

    return key_in, key_out


class ConnectionEncryptor:
    def __init__(self, eEndpoint: 'DatagramEndpoint'):
        self.counter = 0 # 8B
        self.eEndpoint = eEndpoint

        self.ready: Union[None, bool] = False
        self.not_ready_queue = Queue()

        self.encryption_type: int = 0
        self.keyid: tuple[int, int] = (0, 0)
        self.domain: str | None = None
        self._session_root64: Optional[bytes] = None
        self.processing_lock = asyncio.Lock()
        self.initial_send_task: Optional[asyncio.Task] = None
        self.key_fetching = False
        self._prev_key_in: Optional[bytes] = None
        self.__rng = random.Random(int.from_bytes(os.urandom(32), 'big'))

    def rand2(self) -> int:
        return self.__rng.getrandbits(16)

    def _set_transport_keys(self, key_in: bytes, key_out: bytes) -> None:
        if len(key_in) != 32 or len(key_out) != 32:
            raise ValueError('Transport keys must be 32 bytes each')

        if hasattr(self, '_key_in'):
            self._prev_key_in = self._key_in

        self._key_in = key_in
        self._key_out = key_out

    def getSessionRoot64(self) -> Optional[bytes]:
        return self._session_root64

    def setSessionRoot64(self, root64: bytes, peer_domain: str) -> None:
        self_domain = self.eEndpoint._kdc._client._domain
        key_in, key_out = derive_transport_keys_from_root64(
            root64,
            local_domain=self_domain,
            peer_domain=peer_domain,
        )
        self._set_transport_keys(key_in, key_out)
        self._session_root64 = root64
        _prequic_log(
            f"setSessionRoot64 root64_fp={hashlib.sha3_256(root64).hexdigest()[:16]} "
            f"self_domain={self_domain!r} peer_domain={peer_domain!r} "
            f"key_in_fp={hashlib.sha3_256(key_in).hexdigest()[:16]} "
            f"key_out_fp={hashlib.sha3_256(key_out).hexdigest()[:16]}"
        )

    def setSessionRoot64_receive_only(self, root64: bytes, peer_domain: str, *, local_domain: str | None = None) -> None:
        """Immediately update _key_in for PQ decryption while keeping old _key_out.

        This is used during the handshake-to-PQ transition: the receiving side
        must accept both old (HKDF) and new (PQ) packets immediately, while the
        sending side keeps the old key until the next event-loop tick so the
        remote peer has time to prepare its own _key_in.
        """
        self_domain = local_domain if local_domain is not None else self.eEndpoint._kdc._client._domain
        key_in, key_out = derive_transport_keys_from_root64(
            root64,
            local_domain=self_domain,
            peer_domain=peer_domain,
        )
        if hasattr(self, '_key_in'):
            self._prev_key_in = self._key_in
        self._key_in = key_in
        self._pending_key_out = key_out
        self._session_root64 = root64
        _prequic_log(
            f"setSessionRoot64_receive_only root64_fp={hashlib.sha3_256(root64).hexdigest()[:16]} "
            f"self_domain={self_domain!r} peer_domain={peer_domain!r} "
            f"key_in_fp={hashlib.sha3_256(key_in).hexdigest()[:16]} "
            f"key_out_fp={hashlib.sha3_256(key_out).hexdigest()[:16]} (pending)"
        )

    def applyPendingKeyOut(self) -> None:
        """Apply the deferred _key_out switch queued by setSessionRoot64_receive_only."""
        pending = getattr(self, '_pending_key_out', None)
        if pending is not None:
            self._key_out = pending
            self._pending_key_out = None
            _prequic_log(f"applyPendingKeyOut applied for domain={self.domain!r}")

    def hasPendingKeyOut(self) -> bool:
        return getattr(self, '_pending_key_out', None) is not None

    def hasTransportKeys(self) -> bool:
        return hasattr(self, '_key_in') and hasattr(self, '_key_out')

    def debug_state(self) -> str:
        return (
            f"ready={self.ready} enc_type={self.encryption_type} keyid={self.keyid} "
            f"domain={self.domain!r} has_keys={self.hasTransportKeys()} "
            f"session_root={'set' if self._session_root64 is not None else 'none'} "
            f"queue={self.not_ready_queue.qsize()} key_fetching={self.key_fetching}"
        )

    def restoreInactiveSession(
        self,
        *,
        encryption_type: int,
        keyid: tuple[int, int],
        root64: bytes,
        peer_domain: str,
    ) -> None:
        self.encryption_type = encryption_type
        self.keyid = keyid
        self.domain = peer_domain
        self.ready = True
        self.setSessionRoot64(root64, peer_domain)


    async def initByKeyid(self, encryption_type: int, keyid: tuple[int, int]) -> str:
        self.encryption_type = encryption_type
        self.keyid = keyid
        self._session_root64 = None
        await self.eEndpoint._kdc.requestKeyIfNotExist(keyid)

        key = self.eEndpoint._kdc.getKey(keyid)
        
        DestDomain = self.eEndpoint._kdc.getDomainById(cast(Any, keyid))

        if DestDomain is None:
            raise AllGNFastCommands.transport.KeyDomainNotFound({'keyid': keyid})

        self_domain = self.eEndpoint._kdc._client._domain
        key_in, key_out = _derive_bootstrap_transport_keys(
            key,
            local_domain=self_domain,
            peer_domain=DestDomain,
        )
        self._set_transport_keys(key_in, key_out)

        self.ready = True
        self.domain = DestDomain
        _prequic_log(
            f"initByKeyid success local_domain={self.eEndpoint._domain!r} peer_domain={DestDomain!r} "
            f"state={self.debug_state()}"
        )
        return DestDomain

    async def initRaw(self):
        self.encryption_type = 0
        self.keyid = (0, 0)
        self._session_root64 = None
        self.ready = True
        _prequic_log(f"initRaw success local_domain={self.eEndpoint._domain!r} state={self.debug_state()}")

    async def initType2(self, *, is_server: bool = False):
        self.encryption_type = 2
        self.keyid = (250, 0)
        self._session_root64 = None

        if is_server:
            local_marker, peer_marker = 'pq:server', 'pq:client'
        else:
            local_marker, peer_marker = 'pq:client', 'pq:server'

        key_in, key_out = _derive_bootstrap_transport_keys(
            b'',
            local_domain=local_marker,
            peer_domain=peer_marker,
        )
        self._set_transport_keys(key_in, key_out)

        self.ready = True
        self.domain = self.eEndpoint._domain
        _prequic_log(
            f"initType2 success is_server={is_server} local_domain={self.eEndpoint._domain!r} "
            f"key_in_fp={hashlib.sha3_256(key_in).hexdigest()[:16]} key_out_fp={hashlib.sha3_256(key_out).hexdigest()[:16]} "
            f"state={self.debug_state()}"
        )

    
    async def initByDomain(self, encryption_type: int, domain: str) -> tuple[int, int]:

        self.encryption_type = encryption_type
        self._session_root64 = None
        if encryption_type == 0:
            await self.initRaw()
            return (0, 0)

        if encryption_type == 2:
            await self.initType2()
            return (250, 0)

        await self.eEndpoint._kdc.requestKeyIfNotExist(domain)

        self.keyid = self.eEndpoint._kdc.getKeyIdByDomain(domain)

        if self.keyid is None:
            self.keyid = (0, 0)
            raise AllGNFastCommands.transport.KeyIdNotFound({'domain': domain})
        
        key = self.eEndpoint._kdc.getKey(self.keyid) # type: ignore

        self_domain = self.eEndpoint._kdc._client._domain
        key_in, key_out = _derive_bootstrap_transport_keys(
            key,
            local_domain=self_domain,
            peer_domain=domain,
        )
        self._set_transport_keys(key_in, key_out)

        self.ready = True
        self.domain = domain
        _prequic_log(
            f"initByDomain success local_domain={self.eEndpoint._domain!r} peer_domain={domain!r} "
            f"state={self.debug_state()}"
        )
        return self.keyid


    def _make_nonce(self) -> bytes: # 15B
        now = int(time.time()) & 0xFFFFFFFFFF
        self.counter = (self.counter + 1) & 0xFFFFFFFFFFFFFFFF
        return now.to_bytes(5, "big") + self.counter.to_bytes(8, "big") + self.rand2().to_bytes(2, "big")
    
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
        try:
            cipher = AES.new(self._key_in, AES.MODE_OCB, nonce=nonce, mac_len=16)
            result = cipher.decrypt_and_verify(ciphertext, tag)
            if self._prev_key_in is not None:
                if self.hasPendingKeyOut():
                    self.applyPendingKeyOut()
                self._prev_key_in = None
            return result
        except Exception:
            prev = self._prev_key_in
            if prev is not None:
                cipher = AES.new(prev, AES.MODE_OCB, nonce=nonce, mac_len=16)
                return cipher.decrypt_and_verify(ciphertext, tag)
            raise




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

        # GN pre-QUIC Initial packets carry 9 more bytes of framing than regular packets.
        # Keep both client and server on the Initial-safe limit until the handshake completes.
        self._quic._max_datagram_size = self._upd_datagram_size - 9

    def setDefault_max_datagram_size(self):
        self._quic._max_datagram_size = self._upd_datagram_size

    def _debug_runtime_state(self) -> str:
        tls_context = getattr(self._quic, 'tls', None)
        tls_state = getattr(tls_context, 'state', None)
        host_cids = [
            _format_cid(connection_id.cid)
            for connection_id in getattr(self._quic, '_host_cids', [])
        ]
        return (
            f"connected={self._connected} handshake_complete={getattr(self._quic, '_handshake_complete', None)} "
            f"tls_state={tls_state} host_cids={host_cids[:4]}"
        )

    def datagram_received(self, data, addr) -> None:
        try:
            super().datagram_received(data, addr)
        except Exception:
            data = cast(bytes, data)
            desc = 'unknown'
            try:
                host_cid_length = getattr(getattr(self._quic, '_configuration', None), 'connection_id_length', None)
                header = pull_quic_header(Buffer(data=data), host_cid_length=host_cid_length)
                extra = max(0, len(data) - header.packet_length)
                desc = (
                    f"type={header.packet_type.name.lower()} len={header.packet_length}/{len(data)} "
                    f"version={header.version} dcid={_format_cid(header.destination_cid)} "
                    f"scid={_format_cid(header.source_cid)} token_len={len(header.token)} extra={extra}"
                )
            except Exception:
                desc = f"parse-error len={len(data)} first={data[:8].hex()}"
            _prequic_log(
                f"protocol datagram_received error addr={addr} quic={desc} state={self._debug_runtime_state()} "
                f"trace={traceback.format_exc()}"
            )
            raise

      

    def _apply_gn_pq_session_root(self, peer_domain: Optional[str]) -> bool:
        if not peer_domain:
            _prequic_log(f"_apply_gn_pq_session_root skip: no peer_domain")
            return False

        established = getattr(self._quic, "gn_pq_established_state", None)
        if established is None:
            _prequic_log(f"_apply_gn_pq_session_root skip: no established state for peer={peer_domain!r}")
            return False

        network_paths = getattr(self._quic, "_network_paths", None)
        if not network_paths:
            _prequic_log(f"_apply_gn_pq_session_root skip: no network_paths for peer={peer_domain!r}")
            return False

        addr = network_paths[0].addr
        maddr = DatagramEndpoint.from_addr_to_maddr(addr)
        connectionEnc = self.datagramEndpoint.getDgEnc(maddr)

        _prequic_log(
            f"_apply_gn_pq_session_root peer={peer_domain!r} maddr={maddr} "
            f"enc_type={connectionEnc.encryption_type} state={connectionEnc.debug_state()}"
        )

        # Mid-connection upgrade from raw UDP framing would need an explicit epoch switch.
        # Only rekey already-encrypted pre-QUIC associations here.
        if connectionEnc.encryption_type == 0:
            _prequic_log(f"_apply_gn_pq_session_root skip: encryption_type=0 for peer={peer_domain!r}")
            return False

        if connectionEnc.getSessionRoot64() == established.root64:
            _prequic_log(f"_apply_gn_pq_session_root skip: root64 already set for peer={peer_domain!r}")
            return True

        # For encType 2 (PQ+TLS, no KDC) prefer authenticated logical domains.
        # If the client did not present a verified GN PQ certificate, keep the
        # legacy anonymous marker so transport keys stay compatible.
        if connectionEnc.encryption_type == 2:
            is_client = getattr(self._quic, '_is_client', False)
            tls_ctx = getattr(self._quic, 'tls', None)
            if is_client:
                pq_server_hello = getattr(tls_ctx, '_gn_pq_server_hello', None) if tls_ctx else None
                if pq_server_hello is not None:
                    server_cert_domain = pq_server_hello.server_certificate.name
                else:
                    server_cert_domain = peer_domain

                client_settings = getattr(tls_ctx, '_gn_pq_client_settings', None) if tls_ctx else None
                client_identity = getattr(client_settings, 'client_identity', None) if client_settings else None
                verified_client_domain = client_identity.certificate.name if client_identity is not None else None

                eff_local = verified_client_domain if verified_client_domain is not None else "pq:anonymous"
                eff_peer = server_cert_domain
            else:
                server_cert_domain = connectionEnc.eEndpoint._kdc._client._domain
                verified_client_domain = getattr(tls_ctx, '_gn_pq_authenticated_client_domain', None) if tls_ctx else None
                eff_local = server_cert_domain
                eff_peer = verified_client_domain if verified_client_domain is not None else "pq:anonymous"
            connectionEnc.setSessionRoot64_receive_only(
                established.root64, eff_peer, local_domain=eff_local
            )
        else:
            connectionEnc.setSessionRoot64_receive_only(established.root64, peer_domain)
        connectionEnc.domain = peer_domain
        if getattr(self._quic, '_is_client', False):
            _prequic_log(
                f"_apply_gn_pq_session_root client deferred send-side switch until inbound new-key packet for peer={peer_domain!r}"
            )
        else:
            asyncio.get_event_loop().call_soon(connectionEnc.applyPendingKeyOut)
        if connectionEnc.encryption_type == 2:
            _prequic_log(
                f"_apply_gn_pq_session_root OK"
                f"{peer_domain!r} {connectionEnc.encryption_type} {connectionEnc.keyid}"
            )
        else:
            _prequic_log(f"_apply_gn_pq_session_root OK: receive-side switched, send-side deferred for peer={peer_domain!r}")
        return True


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
        


    def sendMapped(self, data: bytes, addr=None, *, _maddr=None):
        if _maddr is None:
            _maddr = DatagramEndpoint.from_addr_to_maddr(addr)
        if _maddr in self.tablex_maddr_isV4:
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

        self.__info_dg_count = 0
        self._payload_b0 = bytes([((self._gn_protocol_version & 0x7F) << 1)])
    
    def __info_dg_count_s(self):
        return
        logger.debug(f"datagrams: got={self.__info_dg_count}")

    async def _is_kdc_bootstrap_allowed_for_local_domain(self) -> bool:
        if self._domain is None:
            return True
        return await self.DEPConfig.isKDCAllowedForDomain(self._domain)

    async def _is_confirmed_kdc_domain_allowed(self, domain: Optional[str]) -> bool:
        if domain is None:
            return False
        return await self.DEPConfig.isConfirmedKDCDomainAllowed(domain)

    def _get_confirmed_kdc_domain(self, keyid: Tuple[int, int]) -> Optional[str]:
        if self._kdc.getKey(keyid) is None:
            return None
        return self._kdc.getDomainById(keyid)
    
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

    def _get_quic_host_cid_length(self) -> Optional[int]:
        quic_obj = getattr(self._quic_routing, '_quic', None)
        if quic_obj is not None:
            config = getattr(quic_obj, '_configuration', None)
            if config is not None:
                return getattr(config, 'connection_id_length', None)

        config = getattr(self._quic_routing, '_configuration', None)
        if config is not None:
            return getattr(config, 'connection_id_length', None)

        return None

    def _describe_quic_datagram(self, data: bytes) -> str:
        if not data:
            return 'empty'

        host_cid_length = self._get_quic_host_cid_length()
        try:
            header = pull_quic_header(Buffer(data=data), host_cid_length=host_cid_length)
            extra = max(0, len(data) - header.packet_length)
            return (
                f"type={header.packet_type.name.lower()} len={header.packet_length}/{len(data)} "
                f"version={header.version} dcid={_format_cid(header.destination_cid)} "
                f"scid={_format_cid(header.source_cid)} token_len={len(header.token)} extra={extra}"
            )
        except Exception as exc:
            return f"parse-error={type(exc).__name__}: {exc} len={len(data)} first={data[:8].hex()}"

    def _describe_routing_state(self) -> str:
        if isinstance(self._quic_routing, QuicProtocolShell):
            return self._quic_routing._debug_runtime_state()
        return f"routing=server protocols={len(getattr(self._quic_routing, '_protocols', {}))}"

    def _describe_cid_match(self, data: bytes) -> str:
        if not isinstance(self._quic_routing, QuicProtocolShell):
            return 'cid_match=server-routing'

        host_cid_length = self._get_quic_host_cid_length()
        try:
            header = pull_quic_header(Buffer(data=data), host_cid_length=host_cid_length)
        except Exception as exc:
            return f'cid_match=parse-error={type(exc).__name__}: {exc}'

        host_cids = [
            connection_id.cid
            for connection_id in getattr(self._quic_routing._quic, '_host_cids', [])
        ]
        matched = any(header.destination_cid == cid for cid in host_cids)
        return (
            f"cid_match={matched} dcid={_format_cid(header.destination_cid)} "
            f"host_cids={[ _format_cid(cid) for cid in host_cids[:4] ]}"
        )

    def _inactive_transport_session_limit(self) -> int:
        return max(1, int(getattr(self.DEPConfig, 'max_inactive_transport_sessions', 8192) or 1))

    def _remember_inactive_connection(self, connectionEnc: ConnectionEncryptor) -> None:
        root64 = connectionEnc.getSessionRoot64()
        if root64 is None or connectionEnc.domain is None or connectionEnc.encryption_type == 0:
            return

        self._kdc.rememberInactiveTransportSession(
            domain=connectionEnc.domain,
            keyid=connectionEnc.keyid,
            encryption_type=connectionEnc.encryption_type,
            root64=root64,
            max_sessions=self._inactive_transport_session_limit(),
        )

    def _restore_connection_from_inactive_domain(self, connectionEnc: ConnectionEncryptor, domain: str) -> bool:
        session = self._kdc.getInactiveTransportSessionByDomain(domain)
        if session is None:
            return False

        connectionEnc.restoreInactiveSession(
            encryption_type=session.encryption_type,
            keyid=session.keyid,
            root64=session.root64,
            peer_domain=session.domain,
        )
        return True

    def _restore_connection_from_inactive_keyid(self, connectionEnc: ConnectionEncryptor, keyid: Tuple[int, int]) -> bool:
        session = self._kdc.getInactiveTransportSessionByKeyId(keyid)
        if session is None:
            return False

        connectionEnc.restoreInactiveSession(
            encryption_type=session.encryption_type,
            keyid=session.keyid,
            root64=session.root64,
            peer_domain=session.domain,
        )
        return True

    def getPeerKdcKey(self, proto: QuicProtocolShell) -> Optional[bytes]:
        local_domain = self._kdc._client._domain
        if local_domain not in (self._kdc._kdc_domain, self._kdc._second_kdc_domain):
            return None

        network_paths = getattr(proto._quic, '_network_paths', None)
        if not network_paths:
            return None

        maddr = self.from_addr_to_maddr(network_paths[0].addr)
        connectionEnc = self.x_maddr_dgEnc.get(maddr)
        if connectionEnc is None or connectionEnc.keyid == (0, 0):
            return None

        return self._kdc.getKey(connectionEnc.keyid)

    def markProtocolInactive(self, proto: QuicProtocolShell) -> None:
        network_paths = getattr(proto._quic, '_network_paths', None)
        peer_maddr = getattr(proto, '_peer_maddr', None)

        if network_paths:
            maddr = self.from_addr_to_maddr(network_paths[0].addr)
        elif peer_maddr is not None:
            maddr = peer_maddr
        else:
            return

        connectionEnc = self.x_maddr_dgEnc.pop(maddr, None)
        if connectionEnc is None:
            return

        self._remember_inactive_connection(connectionEnc)

    async def _init_encrypted_initial_connection(
        self,
        connectionEnc: ConnectionEncryptor,
        encryption_type: int,
        keyid: Tuple[int, int],
        data: bytes,
        addr,
    ) -> Optional[str]:
        confirmed_domain = self._get_confirmed_kdc_domain(keyid)
        confirmed_domain_allowed = await self._is_confirmed_kdc_domain_allowed(confirmed_domain)

        if not confirmed_domain_allowed and not await self._is_kdc_bootstrap_allowed_for_local_domain():
            connectionEnc.ready = None
            raise AllGNFastCommands.transport.PolicyDenied({
                'policy': 'kdc_allowed_domains',
                'domain': self._domain,
            })

        if confirmed_domain_allowed:
            _prequic_log(
                f"_init_encrypted_initial_connection confirmed-domain bypass keyid={keyid} domain={confirmed_domain!r}"
            )

        if not self._kdc._active_key_synchronization:
            key = self._kdc.getKey(keyid)
            if key is None:
                connectionEnc.ready = None
                raise AllGNFastCommands.transport.PolicyDenied({
                    'policy': 'kdc_active_key_synchronization',
                    'keyid': keyid,
                })

        if self._kdc.getKey(keyid) is None:
            connectionEnc.not_ready_queue.put_nowait((data, addr))
            if not connectionEnc.key_fetching:
                connectionEnc.key_fetching = True
                self.loop.create_task(self._fetch_key_and_resume(connectionEnc, encryption_type, keyid))
            return None

        d = await connectionEnc.initByKeyid(encryption_type, keyid)
        if (
            not confirmed_domain_allowed
            and self.active_key_synchronization_callback_domain_filter is not None
            and not self.active_key_synchronization_callback_domain_filter.match_any(d)
            and not GNDomain.isCore(d)
        ):
            connectionEnc.ready = None
            raise AllGNFastCommands.transport.PolicyDenied({
                'domain': d,
                'policy': 'active_key_synchronization_callback_domain_filter',
                'filter': self.DEPConfig.kdc_active_key_synchronization_domain_filter,
            })

        return d

    async def _init_unencrypted_initial_connection(self, connectionEnc: ConnectionEncryptor, maddr: Tuple[str, int, int]) -> str:
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
        return d

    async def _init_pq_initial_connection(self, connectionEnc: ConnectionEncryptor, maddr: Tuple[str, int, int]) -> str:
        await connectionEnc.initType2(is_server=True)
        d = Url.ip_and_port_to_ipv6_with_port(maddr[0], maddr[1])
        connectionEnc.domain = d
        _prequic_log(f"_init_pq_initial_connection success addr={maddr} domain={d!r} state={connectionEnc.debug_state()}")
        return d

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
            logger.warning(f'UDP key fetch error: {traceback.format_exc()}')
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
                logger.error(f'UDP worker[{worker_id}] error: {traceback.format_exc()}')
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

        # ── fast path: payload packet on warm unencrypted connection ──
        # Encrypted peers must stay on the worker path so per-peer processing
        # remains serialized while bootstrap / PQ transport keys are changing.
        if len(data) > 1 and not (data[0] & 0x01):
            version = (data[0] >> 1) & 0x7F
            if version == self._gn_protocol_version:
                maddr = self.from_addr_to_maddr(addr)
                connectionEnc = self.x_maddr_dgEnc.get(maddr)
                if connectionEnc is not None and connectionEnc.ready:
                    if connectionEnc.encryption_type == 0:
                        dec = data[1:]
                        self.__info_dg_count += 1
                        self._quic_routing.datagram_received(dec, addr)
                        self.__info_dg_count_s()
                        return

        # ── slow path: queue for async worker ──
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
                logger.warning(
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
            _prequic_log(
                f"sendto initial addr={maddr} local_domain={self._domain!r} "
                f"default_enc={self._default_encryption_type} state={connectionEnc.debug_state()}"
            )

            if self._domain is None:
                _prequic_log(f"sendto initial dropped: local domain is None addr={maddr} state={connectionEnc.debug_state()}")
            elif connectionEnc.ready:
                self._send_initial_datagram(connectionEnc, data, addr, connectionEnc.keyid)
                return
            else:
                if connectionEnc.initial_send_task is None or connectionEnc.initial_send_task.done():
                    connectionEnc.initial_send_task = self.loop.create_task(self.async_sendto(connectionEnc, data, addr))
                else:
                    _prequic_log(
                        f"sendto initial queued addr={maddr} reason=initial-task-running state={connectionEnc.debug_state()}"
                    )
                    connectionEnc.not_ready_queue.put_nowait((data, addr))
                return

        if not connectionEnc.ready:
            _prequic_log(f"sendto queued addr={maddr} reason=not-ready state={connectionEnc.debug_state()}")
            connectionEnc.not_ready_queue.put_nowait((data, addr))
            return

        #print(connectionEnc.domain, connectionEnc.encryption_type, connectionEnc.keyid)
        if connectionEnc.encryption_type != 0 and connectionEnc.hasTransportKeys():
            # try:
            #     print(connectionEnc._key_in, connectionEnc._key_out)
            # except: pass
            try:
                enc = connectionEnc.encrypt(data)
            except Exception:
                _prequic_log(
                    f"sendto payload encryption failed addr={maddr} state={connectionEnc.debug_state()} "
                    f"trace={traceback.format_exc()}"
                )
                return
        else:
            enc = data

        self.transport.sendMapped(self._payload_b0 + enc, addr, _maddr=maddr)

    def _send_initial_datagram(self, connectionEnc: 'ConnectionEncryptor', data: bytes, addr, keyid) -> None:
        maddr = self.from_addr_to_maddr(addr)
        effective_encryption_type = connectionEnc.encryption_type
        p = self.construct_initial(effective_encryption_type, keyid) # type: ignore
        _prequic_log(
            f"async_sendto prepared initial addr={maddr} effective_enc={effective_encryption_type} keyid={keyid} "
            f"quic={self._describe_quic_datagram(data)} state={connectionEnc.debug_state()}"
        )

        if effective_encryption_type != 0 and connectionEnc.hasTransportKeys():
            try:
                enc = connectionEnc.encrypt(data)
                _prequic_log(
                    f"async_sendto initial ENCRYPTED addr={maddr} plaintext_len={len(data)} cipher_len={len(enc)} "
                    f"key_out_fp={hashlib.sha3_256(connectionEnc._key_out).hexdigest()[:16]} state={connectionEnc.debug_state()}"
                )
            except Exception:
                _prequic_log(
                    f"async_sendto initial encryption failed addr={maddr} effective_enc={effective_encryption_type} "
                    f"state={connectionEnc.debug_state()} trace={traceback.format_exc()}"
                )
                return
        else:
            enc = data
            _prequic_log(
                f"async_sendto initial PLAINTEXT addr={maddr} len={len(data)} "
                f"effective_enc={effective_encryption_type} has_keys={connectionEnc.hasTransportKeys()} "
                f"state={connectionEnc.debug_state()}"
            )

        dg = p + enc
        _prequic_log(f"async_sendto sendMapped addr={maddr} datagram_len={len(dg)} state={connectionEnc.debug_state()}")
        self.transport.sendMapped(dg, addr)

    async def async_sendto(self, connectionEnc: 'ConnectionEncryptor', data: bytes, addr):
        maddr = self.from_addr_to_maddr(addr)
        _prequic_log(
            f"async_sendto start addr={maddr} local_domain={self._domain!r} default_enc={self._default_encryption_type} "
            f"state={connectionEnc.debug_state()}"
        )
        current_task = asyncio.current_task()
        try:
            if not connectionEnc.ready:
                keyid = await connectionEnc.initByDomain(self._default_encryption_type, cast(str, self._domain))
            else:
                keyid = connectionEnc.keyid

            self._send_initial_datagram(connectionEnc, data, addr, keyid)

            if not connectionEnc.not_ready_queue.empty():
                while not connectionEnc.not_ready_queue.empty():
                    data, addr = connectionEnc.not_ready_queue.get_nowait()
                    self.sendto(data, addr)
        finally:
            if connectionEnc.initial_send_task is current_task:
                connectionEnc.initial_send_task = None
        

    async def _handle_datagram(self, data: bytes, addr):
        if not data:
            _prequic_log(f"handle datagram dropped: empty payload addr={addr}")
            return
        
        self.__info_dg_count += 1
        self.__info_dg_count_s()
        
        value = (data[0] >> 1) & 0x7F
        if value != self._gn_protocol_version:
            _prequic_log(
                f"handle datagram dropped: version mismatch addr={addr} got={value} expected={self._gn_protocol_version} len={len(data)}"
            )
            return
        
        maddr = self.from_addr_to_maddr(addr)


        connectionEnc  = self.getDgEnc(maddr)
        if connectionEnc.ready is None:
            logger.warning(f'UDP: datagramm blocked ({maddr})')

        d = None

        if data[0] & 0x01: # если системный пакет.
            if len(data) < 10:
                _prequic_log(f"handle system packet dropped: too short addr={maddr} len={len(data)}")
                return
            commnd_id = (data[1] >> 4) & 0x0F
            datagram = data[10:]
            if commnd_id == 0: # initial
                if len(addr) == 2:
                    self.transport.addV4maddr(maddr)

                encryption_type = data[1] & 0x0F
                incoming_keyid: Optional[Tuple[int, int]] = None
                if encryption_type != 0:
                    keyType = data[2]
                    key_id = int.from_bytes(data[3:10], 'big')
                    incoming_keyid = (keyType, key_id)

                _prequic_log(
                    f"handle initial addr={maddr} incoming_enc={encryption_type} incoming_keyid={incoming_keyid} "
                    f"local_domain={self._domain!r} state_before={connectionEnc.debug_state()}"
                )

                if not connectionEnc.ready:
                    if encryption_type == 2: # PQ only (no KDC)
                        d = await self._init_pq_initial_connection(connectionEnc, maddr)
                    elif encryption_type != 0: # KDC encrypted
                        d = await self._init_encrypted_initial_connection(connectionEnc, encryption_type, cast(Tuple[int, int], incoming_keyid), data, addr)
                        if d is None:
                            return
                    else:
                        d = await self._init_unencrypted_initial_connection(connectionEnc, maddr)

                    while not connectionEnc.not_ready_queue.empty():
                        raw, a = connectionEnc.not_ready_queue.get_nowait()
                        await self._handle_datagram(raw, a)
                else:
                    # Existing UDP association can still open new QUIC connections with new destination CID.
                    # Reuse the established transport state for repeated QUIC connections.
                    # Only refresh when the transport association itself changes.

                    if encryption_type == 2: # PQ only (no KDC)
                        # Server: reinitialize bootstrap keys (a new client
                        # connection after PQ rekey needs fresh bootstrap keys).
                        # Client: keep existing keys — the server's initial
                        # response must be decrypted with the SAME key pair.
                        if connectionEnc.encryption_type != 2 or isinstance(self._quic_routing, QuicServer):
                            d = await self._init_pq_initial_connection(connectionEnc, maddr)
                        else:
                            d = connectionEnc.domain
                    elif encryption_type != 0:
                        if connectionEnc.keyid != incoming_keyid or connectionEnc.encryption_type != encryption_type:
                            d = await self._init_encrypted_initial_connection(connectionEnc, encryption_type, cast(Tuple[int, int], incoming_keyid), data, addr)
                            if d is None:
                                return
                        else:
                            d = self._kdc.getDomainById(cast(Any, incoming_keyid))
                            if d is None:
                                d = connectionEnc.domain
                    else:
                        if connectionEnc.encryption_type != 0:
                            d = await self._init_unencrypted_initial_connection(connectionEnc, maddr)
                        else:
                            d = Url.ip_and_port_to_ipv6_with_port(maddr[0], maddr[1])

                    if d is not None:
                        connectionEnc.domain = d
                _prequic_log(
                    f"handle initial done addr={maddr} resolved_domain={d!r} state_after={connectionEnc.debug_state()}"
                )
            else:
                _prequic_log(
                    f"handle system packet addr={maddr} command_id={commnd_id} wrapped_len={len(data)} state={connectionEnc.debug_state()}"
                )
        else:
            datagram = data[1:]

            # _prequic_log(
            #     f"handle payload packet addr={maddr} wrapped_len={len(data)} state_before={connectionEnc.debug_state()}"
            # )

            if not connectionEnc.ready:
                _prequic_log(f"handle payload queued addr={maddr} reason=not-ready state={connectionEnc.debug_state()}")
                connectionEnc.not_ready_queue.put_nowait((data, addr))
                return

        if connectionEnc.encryption_type != 0 and connectionEnc.hasTransportKeys():
            try:
                dec = connectionEnc.decrypt(datagram)
                
            except Exception as e:
                key_in_fp = hashlib.sha3_256(connectionEnc._key_in).hexdigest()[:16] if hasattr(connectionEnc, '_key_in') else 'none'
                prev_fp = hashlib.sha3_256(connectionEnc._prev_key_in).hexdigest()[:16] if hasattr(connectionEnc, '_prev_key_in') and connectionEnc._prev_key_in else 'none'
                root64_fp = hashlib.sha3_256(connectionEnc._session_root64).hexdigest()[:16] if connectionEnc._session_root64 else 'none'
                # Check if the payload looks like a plaintext QUIC packet (bit 6 "fixed bit" set)
                looks_plaintext = len(datagram) > 0 and (datagram[0] & 0x40) != 0
                logger.error(
                    f"UDP: UPD Decryption error: {e} datagram_len={len(datagram)} first4={datagram[:4].hex() if len(datagram) >= 4 else 'short'} looks_quic_plaintext={looks_plaintext}"
                    f'info:\naddr: {addr}\n'
                    f'{connectionEnc.domain}'
                    f'{connectionEnc.keyid}'
                    f'key_in_fp={key_in_fp} prev_key_in_fp={prev_fp} root64_fp={root64_fp}'
                    f'{connectionEnc.eEndpoint._kdc.getKey(connectionEnc.keyid)}')
                return
        else:
            dec = datagram


        if d is not None and isinstance(self._quic_routing, QuicServer):
            self.add_QuicProtocolShellServer_domain(dec, d)

        try:
            self._quic_routing.datagram_received(dec, addr)
        except Exception:
            _prequic_log(
                f"routing datagram_received error addr={maddr} quic={self._describe_quic_datagram(dec)} "
                f"routing_state={self._describe_routing_state()} trace={traceback.format_exc()}"
            )
            raise


