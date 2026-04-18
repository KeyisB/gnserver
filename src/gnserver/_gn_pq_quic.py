from __future__ import annotations

import datetime
import os
import traceback
from dataclasses import dataclass
from functools import partial
from types import MethodType
from typing import Any, Callable, Optional, Text, Union, cast

from KeyisBTools.bytes.transformation import userFriendly
from aioquic import tls
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.asyncio.server import QuicServer as AioQuicServer
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import NetworkAddress, QuicConnection
from aioquic.quic.packet import (
    QuicPacketType,
    encode_quic_retry,
    encode_quic_version_negotiation,
    pull_quic_header,
)
import aioquic.quic.configuration as quic_configuration

from ._ctr_ca_pub import get_gn_pq_ca_public_key, has_gn_pq_ca_public_keys
from ._gn_pq_handshake import (
    GNPQCertifiedServerIdentity,
    GNPQClientCompletion,
    GNPQClientHandshakeState,
    GNPQEstablishedState,
    _sha3_256_hex,
    build_client_handshake,
    build_server_handshake,
    complete_client_handshake,
    complete_server_handshake,
    get_default_gn_pq_signature_algorithm_name,
    get_gn_pq_signature_artifact_lengths,
    normalize_gn_pq_signature_algorithm_name,
)
from ._gn_pq_session import (
    GNPQClientFinish,
    GNPQClientHello,
    GNPQServerCertificate,
    GNPQServerHello,
)

import logging
logger = logging.getLogger("GNServer.DatagramEndpoint.PQ")


GN_PQ_CLIENT_HELLO_EXTENSION_TYPE = 0xFF80
GN_PQ_SERVER_HELLO_EXTENSION_TYPE = 0xFF81


def _gn_pq_log(message: str) -> None:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    logger.debug(f"[{stamp}] [GN PQ] {message}")


def _format_cid(value: Optional[bytes]) -> str:
    if not value:
        return '-'
    return value.hex()


def _format_tls_state(state: Any) -> str:
    name = getattr(state, "name", None)
    return name if isinstance(name, str) else str(state)


def _format_tls_message_type(message_type: int) -> str:
    try:
        return tls.HandshakeType(message_type).name
    except ValueError:
        return f"UNKNOWN({message_type})"


def _tls_context_role(self: tls.Context) -> str:
    if getattr(self, "_gn_pq_client_settings", None) is not None:
        return "client"
    if getattr(self, "_gn_pq_server_settings", None) is not None:
        return "server"
    return "tls"


def _gn_pq_tls_set_state(self: tls.Context, state: tls.State) -> None:
    previous_state = self.state
    _gn_pq_log(
        "tls state "
        f"role={_tls_context_role(self)} {_format_tls_state(previous_state)}->{_format_tls_state(state)} "
        f"server_hello={getattr(self, '_gn_pq_server_hello', None) is not None} "
        f"client_state={getattr(self, '_gn_pq_client_state', None) is not None} "
        f"server_state={getattr(self, '_gn_pq_server_state', None) is not None}"
    )
    tls.Context._set_state(self, state)


def _gn_pq_tls_handle_reassembled_message(
    self: tls.Context,
    message_type: int,
    input_buf: Buffer,
    output_buf: dict[tls.Epoch, Buffer],
) -> None:
    state_before = self.state
    message_name = _format_tls_message_type(message_type)
    message_len = len(input_buf.data)

    _gn_pq_log(
        "tls dispatch enter "
        f"role={_tls_context_role(self)} state={_format_tls_state(state_before)} "
        f"message={message_name} len={message_len} "
        f"server_hello={getattr(self, '_gn_pq_server_hello', None) is not None}"
    )

    try:
        tls.Context._handle_reassembled_message(self, message_type, input_buf, output_buf)
    except Exception as exc:
        _gn_pq_log(
            "tls dispatch error "
            f"role={_tls_context_role(self)} state={_format_tls_state(self.state)} "
            f"message={message_name} len={message_len} exc={type(exc).__name__}: {exc}"
        )
        raise

    _gn_pq_log(
        "tls dispatch exit "
        f"role={_tls_context_role(self)} state={_format_tls_state(state_before)}->"
        f"{_format_tls_state(self.state)} message={message_name} len={message_len}"
    )


@dataclass(slots=True)
class GNQuicClientSettings:
    server_domain: str
    kdc_key: Optional[bytes] = None


@dataclass(slots=True)
class GNQuicServerSettings:
    server_domain: str
    server_identity: GNPQCertifiedServerIdentity
    kdc_key: Optional[bytes] = None


def _decode_user_friendly_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        try:
            return userFriendly.decode(value)
        except Exception:
            return value.encode("utf-8")
    raise TypeError(f"Unsupported bytes value type: {type(value)!r}")


def _decode_fixed_length_bytes(
    value: Any,
    *,
    expected_length: int,
    field_name: str,
) -> bytes:
    data = _decode_user_friendly_bytes(value)

    if len(data) == expected_length:
        return data
    if len(data) > expected_length:
        raise ValueError(f"{field_name} length must be <= {expected_length} bytes")

    if isinstance(value, str):
        padded = (b"\x00" * (expected_length - len(data))) + data
        _gn_pq_log(
            f"decoded {field_name} shorter than expected ({len(data)}<{expected_length}), left-padding zeros"
        )
        return padded

    raise ValueError(f"{field_name} length must be exactly {expected_length} bytes")


def _parse_crt_public_keys(crt_data: Any) -> dict[str, bytes]:
    if not isinstance(crt_data, dict):
        raise ValueError("gn_server_crt.crypto.crt.data must be a dict")

    algs = crt_data.get("algs")
    if not isinstance(algs, dict) or not algs:
        raise ValueError("gn_server_crt.crypto.crt.data.algs must be a non-empty dict")

    public_keys: dict[str, bytes] = {}
    for algorithm_name, algorithm_data in algs.items():
        if not isinstance(algorithm_name, str) or not algorithm_name:
            raise ValueError("gn_server_crt.crypto.crt.data.algs key must be a non-empty string")
        if not isinstance(algorithm_data, dict):
            raise ValueError("gn_server_crt.crypto.crt.data.algs item must be a dict")
        if "pub" not in algorithm_data:
            raise ValueError("gn_server_crt.crypto.crt.data.algs item must include pub")

        normalized_algorithm = normalize_gn_pq_signature_algorithm_name(algorithm_name)
        public_key_length, _, _ = get_gn_pq_signature_artifact_lengths(normalized_algorithm)

        public_keys[normalized_algorithm] = _decode_fixed_length_bytes(
            algorithm_data["pub"],
            expected_length=public_key_length,
            field_name=f"gn_server_crt.crypto.crt.data.algs[{algorithm_name!r}].pub",
        )

    return public_keys


def _parse_crt_private_keys(crt_container: Any) -> dict[str, bytes]:
    if not isinstance(crt_container, dict):
        raise ValueError("gn_server_crt.crypto.crt must be a dict")

    priv = crt_container.get("priv")
    if not isinstance(priv, dict):
        raise ValueError("gn_server_crt.crypto.crt.priv must be a dict")

    algs = priv.get("algs")
    if not isinstance(algs, dict) or not algs:
        raise ValueError("gn_server_crt.crypto.crt.priv.algs must be a non-empty dict")

    private_keys: dict[str, bytes] = {}
    for algorithm_name, algorithm_data in algs.items():
        if not isinstance(algorithm_name, str) or not algorithm_name:
            raise ValueError("gn_server_crt.crypto.crt.priv.algs key must be a non-empty string")
        if not isinstance(algorithm_data, dict):
            raise ValueError("gn_server_crt.crypto.crt.priv.algs item must be a dict")
        if "priv" not in algorithm_data:
            raise ValueError("gn_server_crt.crypto.crt.priv.algs item must include priv")

        normalized_algorithm = normalize_gn_pq_signature_algorithm_name(algorithm_name)
        _, private_key_length, _ = get_gn_pq_signature_artifact_lengths(normalized_algorithm)

        private_keys[normalized_algorithm] = _decode_fixed_length_bytes(
            algorithm_data["priv"],
            expected_length=private_key_length,
            field_name=f"gn_server_crt.crypto.crt.priv.algs[{algorithm_name!r}].priv",
        )

    return private_keys


def _parse_server_certificate(crt_container: Any) -> GNPQServerCertificate:
    if not isinstance(crt_container, dict):
        raise ValueError("gn_server_crt.crypto.crt must be a dict")

    crt_data = crt_container.get("data")
    signature = crt_container.get("sign")

    if not isinstance(crt_data, dict):
        raise ValueError("gn_server_crt.crypto.crt.data must be a dict")
    if signature is None:
        raise ValueError("gn_server_crt.crypto.crt.sign is required")

    center_domain = crt_data.get("c")
    center_key_version = crt_data.get("c_v")
    server_domain = crt_data.get("domain")
    expires_at = crt_data.get("exp")

    if not isinstance(center_domain, str) or not center_domain:
        raise ValueError("gn_server_crt.crypto.crt.data.c must be a non-empty string")
    if not isinstance(center_key_version, int) or center_key_version < 0:
        raise ValueError("gn_server_crt.crypto.crt.data.c_v must be a non-negative int")
    if not isinstance(server_domain, str) or not server_domain:
        raise ValueError("gn_server_crt.crypto.crt.data.domain must be a non-empty string")
    if not isinstance(expires_at, datetime.datetime):
        raise ValueError("gn_server_crt.crypto.crt.data.exp must be datetime.datetime")

    _, _, signature_length = get_gn_pq_signature_artifact_lengths(
        get_default_gn_pq_signature_algorithm_name()
    )

    return GNPQServerCertificate(
        center_domain=center_domain,
        center_key_version=center_key_version,
        name=server_domain,
        public_keys=_parse_crt_public_keys(crt_data),
        expires_at=expires_at,
        signature=_decode_fixed_length_bytes(
            signature,
            expected_length=signature_length,
            field_name="gn_server_crt.crypto.crt.sign",
        ),
        source_data=dict(crt_data),
    )


def build_gn_pq_client_settings(server_domain: str, kdc_key: Optional[bytes] = None) -> Optional[GNQuicClientSettings]:
    if not has_gn_pq_ca_public_keys():
        _gn_pq_log(f"client settings disabled for {server_domain!r}: no GN PQ CA keys loaded")
        return None

    _gn_pq_log(
        f"client settings enabled for {server_domain!r} kdc_key={'set' if kdc_key is not None else 'none'}"
    )
    return GNQuicClientSettings(
        server_domain=server_domain,
        kdc_key=kdc_key,
    )


def extract_gn_pq_server_settings(gn_server_crt: dict) -> Optional[GNQuicServerSettings]:
    if not isinstance(gn_server_crt, dict):
        raise ValueError("gn_server_crt must be a dict")

    server_domain = gn_server_crt.get("domain")
    if not isinstance(server_domain, str) or not server_domain:
        raise ValueError("gn_server_crt.domain must be a non-empty string")

    crypto = gn_server_crt.get("crypto")
    if not isinstance(crypto, dict):
        raise ValueError("gn_server_crt.crypto must be a dict")

    crt_container = crypto.get("crt")
    if not isinstance(crt_container, dict):
        raise ValueError("gn_server_crt.crypto.crt must be a dict")

    kdc = crypto.get("kdc")
    if kdc is not None and not isinstance(kdc, dict):
        raise ValueError("gn_server_crt.crypto.kdc must be a dict or None")

    certificate = _parse_server_certificate(crt_container)
    if certificate.name != server_domain:
        raise ValueError("gn_server_crt.domain must match gn_server_crt.crypto.crt.data.domain")

    _gn_pq_log(
        f"server loaded certificate domain={server_domain!r} "
        f"ca={certificate.center_domain!r}#{certificate.center_key_version} "
        f"sig_fp={_sha3_256_hex(certificate.signature)[:16]} "
        f"unsigned_fp={_sha3_256_hex(certificate.unsigned_bytes())[:16]} "
        f"unsigned_len={len(certificate.unsigned_bytes())}"
    )

    kdc_key = None
    if isinstance(kdc, dict) and "key" in kdc and kdc["key"] is not None:
        decoded_kdc_key = _decode_user_friendly_bytes(kdc["key"])
        if decoded_kdc_key:
            kdc_key = decoded_kdc_key

    return GNQuicServerSettings(
        server_domain=server_domain,
        server_identity=GNPQCertifiedServerIdentity(
            certificate=certificate,
            private_keys=_parse_crt_private_keys(crt_container),
        ),
        kdc_key=kdc_key,
    )


def _find_extension(extensions: Optional[list[tuple[int, bytes]]], extension_type: int) -> Optional[bytes]:
    if extensions is None:
        return None

    for ext_type, ext_data in extensions:
        if ext_type == extension_type:
            return ext_data
    return None


def _encode_extension_list(extensions: list[tuple[int, bytes]]) -> bytes:
    buf = Buffer(capacity=max(64, sum(len(data) + 4 for _, data in extensions)))
    for extension_type, extension_data in extensions:
        with tls.push_extension(buf, extension_type):
            buf.push_bytes(extension_data)
    return bytes(buf.data)


def _parse_extension_list(data: bytes) -> list[tuple[int, bytes]]:
    buf = Buffer(data=data)
    extensions: list[tuple[int, bytes]] = []
    while not buf.eof():
        extension_type = buf.pull_uint16()
        extension_data = buf.pull_bytes(buf.pull_uint16())
        extensions.append((extension_type, extension_data))
    return extensions


def _store_gn_pq_server_hello(
    self: tls.Context,
    server_hello_payload: bytes,
    *,
    source: str,
) -> None:
    try:
        self._gn_pq_server_hello = GNPQServerHello.from_bytes(server_hello_payload)
    except Exception as exc:
        _gn_pq_log(f"client failed to parse server hello from {source}: {type(exc).__name__}: {exc}")
        raise tls.AlertDecodeError("Invalid GN PQ server hello") from exc

    _gn_pq_log(
        "client received server hello "
        f"source={source} server_domain={self._gn_pq_server_hello.server_certificate.name!r} "
        f"ca={self._gn_pq_server_hello.server_certificate.center_domain!r}#"
        f"{self._gn_pq_server_hello.server_certificate.center_key_version}"
    )


def _gn_pq_client_handle_encrypted_extensions(self: tls.Context, input_buf: Buffer) -> None:
    _gn_pq_log("client handle_encrypted_extensions start")
    try:
        tls.Context._client_handle_encrypted_extensions(self, input_buf)
    except Exception as exc:
        _gn_pq_log(f"client handle_encrypted_extensions base failed: {type(exc).__name__}: {exc}")
        raise
    _gn_pq_log("client handle_encrypted_extensions entered")

    settings = getattr(self, "_gn_pq_client_settings", None)
    if settings is None:
        _gn_pq_log("client handle_encrypted_extensions skipped: no client settings")
        return

    server_hello_payload = _find_extension(self.received_extensions, GN_PQ_SERVER_HELLO_EXTENSION_TYPE)
    if server_hello_payload is None:
        _gn_pq_log("client handle_encrypted_extensions: GN PQ server hello extension missing, waiting for certificate")
        return

    _store_gn_pq_server_hello(self, server_hello_payload, source="encrypted_extensions")


def _gn_pq_client_handle_certificate(self: tls.Context, input_buf: Buffer) -> None:
    settings = getattr(self, "_gn_pq_client_settings", None)

    if settings is None:
        _gn_pq_log("client handle_certificate fallback: no client settings")
        tls.Context._client_handle_certificate(self, input_buf)
        return

    certificate = tls.pull_certificate(Buffer(data=input_buf.data_slice(0, input_buf.capacity)))
    _gn_pq_log(
        "client handle_certificate entered "
        f"entries={len(certificate.certificates)} server_hello={getattr(self, '_gn_pq_server_hello', None) is not None}"
    )

    if certificate.certificates:
        certificate_data, certificate_extensions = certificate.certificates[0]
        _gn_pq_log(
            "client handle_certificate first_entry "
            f"der_len={len(certificate_data)} ext_len={len(certificate_extensions)}"
        )

    if getattr(self, "_gn_pq_server_hello", None) is None and certificate.certificates:
        _, certificate_extensions = certificate.certificates[0]
        try:
            server_hello_payload = _find_extension(
                _parse_extension_list(certificate_extensions),
                GN_PQ_SERVER_HELLO_EXTENSION_TYPE,
            )
        except Exception as exc:
            _gn_pq_log(f"client failed to parse certificate extensions: {type(exc).__name__}: {exc}")
            raise tls.AlertDecodeError("Invalid certificate extensions") from exc

        if server_hello_payload is not None:
            _store_gn_pq_server_hello(self, server_hello_payload, source="certificate")
        else:
            _gn_pq_log("client handle_certificate: GN PQ server hello missing in certificate")

    try:
        tls.Context._client_handle_certificate(self, input_buf)
    except Exception as exc:
        _gn_pq_log(f"client handle_certificate base failed: {type(exc).__name__}: {exc}")
        raise

    _gn_pq_log(f"client handle_certificate base ok next_state={_format_tls_state(self.state)}")


def _gn_pq_client_handle_finished(self: tls.Context, input_buf: Buffer, output_buf: Buffer) -> None:
    settings = getattr(self, "_gn_pq_client_settings", None)
    server_hello = getattr(self, "_gn_pq_server_hello", None)
    client_state = getattr(self, "_gn_pq_client_state", None)

    _gn_pq_log(
        "client handle_finished entered "
        f"settings={settings is not None} server_hello={server_hello is not None} client_state={client_state is not None}"
    )

    if settings is None or server_hello is None or client_state is None:
        _gn_pq_log("client handle_finished fallback to base TLS path")
        tls.Context._client_handle_finished(self, input_buf, output_buf)
        return

    finished = tls.pull_finished(input_buf)

    key_schedule = self.key_schedule
    dec_key = self._dec_key
    enc_key = self._enc_key
    if key_schedule is None or dec_key is None or enc_key is None:
        raise tls.AlertInternalError("GN PQ client handshake keys are not ready")

    expected_verify_data = key_schedule.finished_verify_data(dec_key)
    if finished.verify_data != expected_verify_data:
        raise tls.AlertDecryptError
    key_schedule.update_hash(input_buf.data)

    assert key_schedule.generation == 2
    key_schedule.extract(None)
    self._setup_traffic_protection(
        tls.Direction.DECRYPT, tls.Epoch.ONE_RTT, b"s ap traffic"
    )
    next_enc_key = key_schedule.derive_secret(b"c ap traffic")

    if self._certificate_request is None:
        _gn_pq_log("client finished without certificate request from server")
        raise tls.AlertHandshakeFailure("GN PQ handshake requires a client certificate flight")

    ca_public_key = get_gn_pq_ca_public_key(
        server_hello.server_certificate.center_domain,
        server_hello.server_certificate.center_key_version,
    )
    if ca_public_key is None:
        _gn_pq_log(
            "client missing GN PQ CA key "
            f"{server_hello.server_certificate.center_domain!r}#"
            f"{server_hello.server_certificate.center_key_version}"
        )
        raise tls.AlertBadCertificate(
            "Unknown GN PQ CA key "
            f"{server_hello.server_certificate.center_domain}"
            f"#{server_hello.server_certificate.center_key_version}"
        )

    _gn_pq_log(
        f"client verify ca={server_hello.server_certificate.center_domain!r}#"
        f"{server_hello.server_certificate.center_key_version} "
        f"ca_key_fp={_sha3_256_hex(ca_public_key)[:16]} "
        f"ca_key_len={len(ca_public_key)} "
        f"ca_key_head={ca_public_key[:8].hex()}"
    )

    try:
        completion: GNPQClientCompletion = complete_client_handshake(
            local_server_domain=settings.server_domain,
            client_state=client_state,
            server_hello=server_hello,
            ca_public_key=ca_public_key,
            now_timestamp=tls.utcnow(),
            kdc_key=settings.kdc_key,
        )
    except Exception as exc:
        _gn_pq_log(
            f"client handshake completion failed for {settings.server_domain!r}: "
            f"{type(exc).__name__}: {exc}\n"
            f"{''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))}"
        )
        raise tls.AlertHandshakeFailure("GN PQ client completion failed") from exc

    self._gn_pq_client_completion = completion
    self._gn_pq_established = completion.established
    _gn_pq_log(
        f"client handshake completed for {settings.server_domain!r} "
        f"kdc_key={'set' if settings.kdc_key is not None else 'none'}"
    )

    with tls.push_message(key_schedule, output_buf):
        tls.push_certificate(
            output_buf,
            tls.Certificate(
                request_context=self._certificate_request.request_context,
                certificates=[(b"", completion.client_finish.to_bytes())],
            ),
        )

    with tls.push_message(key_schedule, output_buf):
        tls.push_finished(
            output_buf,
            tls.Finished(
                verify_data=key_schedule.finished_verify_data(enc_key)
            ),
        )

    self._enc_key = next_enc_key
    self.update_traffic_key_cb(
        tls.Direction.ENCRYPT,
        tls.Epoch.ONE_RTT,
        key_schedule.cipher_suite,
        self._enc_key,
    )

    self._set_state(tls.State.CLIENT_POST_HANDSHAKE)


def _gn_pq_server_handle_hello(
    self: tls.Context,
    input_buf: Buffer,
    initial_buf: Buffer,
    handshake_buf: Buffer,
    onertt_buf: Buffer,
) -> None:
    settings = getattr(self, "_gn_pq_server_settings", None)
    if settings is None:
        _gn_pq_log("server handle_hello fallback: no server settings")
        tls.Context._server_handle_hello(self, input_buf, initial_buf, handshake_buf, onertt_buf)
        return

    peer_hello = tls.pull_client_hello(Buffer(data=input_buf.data_slice(0, input_buf.capacity)))
    client_hello_payload = _find_extension(peer_hello.other_extensions, GN_PQ_CLIENT_HELLO_EXTENSION_TYPE)
    if client_hello_payload is None:
        _gn_pq_log(f"server handle_hello: GN PQ client hello extension missing for {settings.server_domain!r}")
        tls.Context._server_handle_hello(self, input_buf, initial_buf, handshake_buf, onertt_buf)
        return

    _gn_pq_log(
        "server handle_hello received client hello "
        f"ext_len={len(client_hello_payload)} peer_extensions={len(peer_hello.other_extensions)}"
    )

    try:
        client_hello = GNPQClientHello.from_bytes(client_hello_payload)
        server_state = build_server_handshake(
            local_server_domain=settings.server_domain,
            server_identity=settings.server_identity,
            client_hello=client_hello,
        )
    except Exception as exc:
        _gn_pq_log(f"server handshake build failed for {settings.server_domain!r}: {type(exc).__name__}: {exc}")
        raise tls.AlertHandshakeFailure("GN PQ server handshake build failed") from exc

    _gn_pq_log(f"server built handshake for {settings.server_domain!r}")

    self._gn_pq_server_state = server_state

    # --- resolve per-peer KDC key via KDCObject ---
    _quic_conn: GNQuicConnection = self._gn_pq_quic_connection
    _dep = _quic_conn._gn_pq_datagram_endpoint
    if _dep is not None and _quic_conn._network_paths:
        from .server._datagram_enc import DatagramEndpoint as _DEP
        _maddr = _DEP.from_addr_to_maddr(_quic_conn._network_paths[0].addr)
        _cEnc = _dep.x_maddr_dgEnc.get(_maddr)
        if _cEnc is not None and _cEnc.keyid != (0, 0):
            self._gn_pq_peer_kdc_key = _dep._kdc.getKey(_cEnc.keyid)
            _gn_pq_log(
                f"server resolved peer kdc key keyid={_cEnc.keyid} "
                f"domain={_cEnc.domain!r}"
            )
    # -----------------------------------------------

    peer_hello = tls.pull_client_hello(input_buf)

    cipher_suite = tls.negotiate(
        self._cipher_suites,
        peer_hello.cipher_suites,
        tls.AlertHandshakeFailure("No supported cipher suite"),
    )
    compression_method = tls.negotiate(
        self._legacy_compression_methods,
        peer_hello.legacy_compression_methods,
        tls.AlertHandshakeFailure("No supported compression method"),
    )
    psk_key_exchange_mode = tls.negotiate(
        self._psk_key_exchange_modes, peer_hello.psk_key_exchange_modes
    )
    signature_algorithm = tls.negotiate(
        self._signature_algorithms_for_private_key(),
        peer_hello.signature_algorithms,
        tls.AlertHandshakeFailure("No supported signature algorithm"),
    )
    supported_version = tls.negotiate(
        self._supported_versions,
        peer_hello.supported_versions,
        tls.AlertProtocolVersion("No supported protocol version"),
    )

    if self._alpn_protocols is not None:
        self.alpn_negotiated = tls.negotiate(
            self._alpn_protocols,
            peer_hello.alpn_protocols,
            tls.AlertHandshakeFailure("No common ALPN protocols"),
        )

    self.client_random = peer_hello.random
    self.server_random = os.urandom(32)
    self.legacy_session_id = peer_hello.legacy_session_id
    self.received_extensions = peer_hello.other_extensions

    if self.alpn_cb and self.alpn_negotiated is not None:
        self.alpn_cb(self.alpn_negotiated)

    pre_shared_key = None
    if (
        self.get_session_ticket_cb is not None
        and psk_key_exchange_mode is not None
        and peer_hello.pre_shared_key is not None
        and len(peer_hello.pre_shared_key.identities) == 1
        and len(peer_hello.pre_shared_key.binders) == 1
    ):
        identity = peer_hello.pre_shared_key.identities[0]
        session_ticket = self.get_session_ticket_cb(identity[0])

        if (
            session_ticket is not None
            and session_ticket.is_valid
            and session_ticket.cipher_suite == cipher_suite
        ):
            self.key_schedule = tls.KeySchedule(cipher_suite)
            self.key_schedule.extract(session_ticket.resumption_secret)

            binder_key = self.key_schedule.derive_secret(b"res binder")
            binder_length = self.key_schedule.algorithm.digest_size

            hash_offset = input_buf.tell() - binder_length - 3
            binder = input_buf.data_slice(
                hash_offset + 3, hash_offset + 3 + binder_length
            )

            self.key_schedule.update_hash(input_buf.data_slice(0, hash_offset))
            expected_binder = self.key_schedule.finished_verify_data(binder_key)

            if binder != expected_binder:
                raise tls.AlertHandshakeFailure("PSK validation failed")

            self.key_schedule.update_hash(
                input_buf.data_slice(hash_offset, hash_offset + 3 + binder_length)
            )
            self._session_resumed = True

            if peer_hello.early_data:
                early_key = self.key_schedule.derive_secret(b"c e traffic")
                self.early_data_accepted = True
                self.update_traffic_key_cb(
                    tls.Direction.DECRYPT,
                    tls.Epoch.ZERO_RTT,
                    self.key_schedule.cipher_suite,
                    early_key,
                )

            pre_shared_key = 0

    if pre_shared_key is None:
        self.key_schedule = tls.KeySchedule(cipher_suite)
        self.key_schedule.extract(None)
        self.key_schedule.update_hash(input_buf.data)

    assert peer_hello.key_share is not None

    public_key: Optional[Union[
        tls.ec.EllipticCurvePublicKey,
        tls.x25519.X25519PublicKey,
        tls.x448.X448PublicKey,
    ]] = None
    shared_key: Optional[bytes] = None
    for key_share in peer_hello.key_share:
        peer_public_key = tls.decode_public_key(key_share)
        if isinstance(peer_public_key, tls.x25519.X25519PublicKey):
            self._x25519_private_key = tls.x25519.X25519PrivateKey.generate()
            public_key = self._x25519_private_key.public_key()
            shared_key = self._x25519_private_key.exchange(peer_public_key)
            break
        if isinstance(peer_public_key, tls.x448.X448PublicKey):
            self._x448_private_key = tls.x448.X448PrivateKey.generate()
            public_key = self._x448_private_key.public_key()
            shared_key = self._x448_private_key.exchange(peer_public_key)
            break
        if isinstance(peer_public_key, tls.ec.EllipticCurvePublicKey):
            ec_private_key = tls.ec.generate_private_key(tls.GROUP_TO_CURVE[key_share[0]]())
            self._ec_private_keys.append(ec_private_key)
            public_key = ec_private_key.public_key()
            shared_key = ec_private_key.exchange(tls.ec.ECDH(), peer_public_key)
            break

    assert shared_key is not None
    assert public_key is not None
    key_schedule = self.key_schedule
    assert key_schedule is not None

    hello = tls.ServerHello(
        random=self.server_random,
        legacy_session_id=self.legacy_session_id,
        cipher_suite=cipher_suite,
        compression_method=compression_method,
        key_share=tls.encode_public_key(public_key),
        pre_shared_key=pre_shared_key,
        supported_version=supported_version,
    )
    with tls.push_message(key_schedule, initial_buf):
        tls.push_server_hello(initial_buf, hello)
    key_schedule.extract(shared_key)

    self._setup_traffic_protection(
        tls.Direction.ENCRYPT, tls.Epoch.HANDSHAKE, b"s hs traffic"
    )
    self._setup_traffic_protection(
        tls.Direction.DECRYPT, tls.Epoch.HANDSHAKE, b"c hs traffic"
    )
    enc_key = self._enc_key
    assert enc_key is not None

    with tls.push_message(key_schedule, handshake_buf):
        tls.push_encrypted_extensions(
            handshake_buf,
            tls.EncryptedExtensions(
                alpn_protocol=self.alpn_negotiated,
                early_data=self.early_data_accepted,
                other_extensions=self.handshake_extensions,
            ),
        )

    if pre_shared_key is None:
        with tls.push_message(key_schedule, handshake_buf):
            tls.push_certificate_request(
                handshake_buf,
                tls.CertificateRequest(
                    request_context=b"",
                    signature_algorithms=self._signature_algorithms,
                ),
            )

        server_hello_bytes = server_state.server_hello.to_bytes()
        server_hello_extensions = _encode_extension_list(
            [(GN_PQ_SERVER_HELLO_EXTENSION_TYPE, server_hello_bytes)]
        )
        _gn_pq_log(
            "server embedded GN PQ server hello into certificate extensions "
            f"server_hello_len={len(server_hello_bytes)} ext_len={len(server_hello_extensions)}"
        )
        certificate_entries = [
            (
                self.certificate.public_bytes(tls.Encoding.DER),
                server_hello_extensions,
            )
        ]
        certificate_entries.extend(
            (certificate.public_bytes(tls.Encoding.DER), b"")
            for certificate in self.certificate_chain
        )

        with tls.push_message(key_schedule, handshake_buf):
            tls.push_certificate(
                handshake_buf,
                tls.Certificate(
                    request_context=b"",
                    certificates=certificate_entries,
                ),
            )

        signature = self.certificate_private_key.sign(
            key_schedule.certificate_verify_data(tls.SERVER_CONTEXT_STRING),
            *tls.signature_algorithm_params(signature_algorithm),
        )
        with tls.push_message(key_schedule, handshake_buf):
            tls.push_certificate_verify(
                handshake_buf,
                tls.CertificateVerify(
                    algorithm=signature_algorithm,
                    signature=signature,
                ),
            )

    with tls.push_message(key_schedule, handshake_buf):
        tls.push_finished(
            handshake_buf,
            tls.Finished(
                verify_data=key_schedule.finished_verify_data(enc_key)
            ),
        )

    assert key_schedule.generation == 2
    key_schedule.extract(None)
    self._setup_traffic_protection(
        tls.Direction.ENCRYPT, tls.Epoch.ONE_RTT, b"s ap traffic"
    )
    self._next_dec_key = key_schedule.derive_secret(b"c ap traffic")

    _gn_pq_log(
        "server handshake flight ready "
        f"initial_len={len(initial_buf.data)} handshake_len={len(handshake_buf.data)} onertt_len={len(onertt_buf.data)}"
    )

    self._psk_key_exchange_mode = psk_key_exchange_mode
    self._set_state(tls.State.SERVER_EXPECT_CERTIFICATE)


def _gn_pq_server_handle_certificate(self: tls.Context, input_buf: Buffer, output_buf: Buffer) -> None:
    settings = getattr(self, "_gn_pq_server_settings", None)
    server_state = getattr(self, "_gn_pq_server_state", None)

    _gn_pq_log(
        "server handle_certificate entered "
        f"settings={settings is not None} server_state={server_state is not None}"
    )

    if settings is None or server_state is None:
        _gn_pq_log("server handle_certificate fallback to base TLS path")
        tls.Context._server_handle_certificate(self, input_buf, output_buf)
        return

    certificate = tls.pull_certificate(input_buf)
    _gn_pq_log(
        "server handle_certificate parsed "
        f"entries={len(certificate.certificates)} state={_format_tls_state(self.state)}"
    )
    self.key_schedule.update_hash(input_buf.data)

    if not certificate.certificates:
        raise tls.AlertHandshakeFailure("Missing GN PQ client finish payload")

    certificate_data, certificate_extensions = certificate.certificates[0]
    _gn_pq_log(
        "server handle_certificate first_entry "
        f"der_len={len(certificate_data)} ext_len={len(certificate_extensions)}"
    )
    if certificate_data != b"":
        raise tls.AlertIllegalParameter("GN PQ client finish must not carry an X.509 certificate")

    try:
        client_finish = GNPQClientFinish.from_bytes(certificate_extensions)
        _gn_pq_log(
            "server handle_certificate decoded client finish "
            f"ciphertext_len={len(client_finish.ml_kem_ciphertext)}"
        )

        kdc_key = self._gn_pq_peer_kdc_key

        established: GNPQEstablishedState = complete_server_handshake(
            local_server_domain=settings.server_domain,
            server_state=server_state,
            client_finish=client_finish,
            kdc_key=kdc_key,
        )
    except Exception as exc:
        _gn_pq_log(f"server handshake completion failed for {settings.server_domain!r}: {type(exc).__name__}: {exc}")
        raise tls.AlertHandshakeFailure("GN PQ server completion failed") from exc

    self._gn_pq_established = established
    _gn_pq_log(
        f"server handshake completed for {settings.server_domain!r} "
        f"kdc_key={'set' if kdc_key is not None else 'none'}"
    )
    self._server_expect_finished(output_buf)
    _gn_pq_log(
        "server queued finished "
        f"onertt_len={len(output_buf.data)} next_state={_format_tls_state(self.state)}"
    )


def _install_gn_pq_tls_hooks(
    context: tls.Context,
    *,
    quic_connection: 'GNQuicConnection',
    client_settings: Optional[GNQuicClientSettings],
    server_settings: Optional[GNQuicServerSettings],
) -> None:
    context._gn_pq_client_settings = client_settings
    context._gn_pq_server_settings = server_settings
    context._gn_pq_client_state = None
    context._gn_pq_server_state = None
    context._gn_pq_server_hello = None
    context._gn_pq_established = None
    context._gn_pq_client_completion = None
    context._gn_pq_quic_connection = quic_connection
    context._gn_pq_peer_kdc_key = None

    _gn_pq_log(
        "install tls hooks "
        f"role={_tls_context_role(context)} client_settings={client_settings is not None} "
        f"server_settings={server_settings is not None}"
    )

    context._handle_reassembled_message = MethodType(_gn_pq_tls_handle_reassembled_message, context)
    context._set_state = MethodType(_gn_pq_tls_set_state, context)
    context._client_handle_encrypted_extensions = MethodType(_gn_pq_client_handle_encrypted_extensions, context)
    context._client_handle_certificate = MethodType(_gn_pq_client_handle_certificate, context)
    context._client_handle_finished = MethodType(_gn_pq_client_handle_finished, context)
    context._server_handle_hello = MethodType(_gn_pq_server_handle_hello, context)
    context._server_handle_certificate = MethodType(_gn_pq_server_handle_certificate, context)


class GNQuicConnection(QuicConnection):
    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        original_destination_connection_id: Optional[bytes] = None,
        retry_source_connection_id: Optional[bytes] = None,
        session_ticket_fetcher: Optional[tls.SessionTicketFetcher] = None,
        session_ticket_handler: Optional[tls.SessionTicketHandler] = None,
        token_handler: Optional[Any] = None,
        gn_pq_client_settings: Optional[GNQuicClientSettings] = None,
        gn_pq_server_settings: Optional[GNQuicServerSettings] = None,
    ) -> None:
        self._gn_pq_client_settings = gn_pq_client_settings
        self._gn_pq_server_settings = gn_pq_server_settings
        self._gn_pq_datagram_endpoint = None
        super().__init__(
            configuration=configuration,
            original_destination_connection_id=original_destination_connection_id,
            retry_source_connection_id=retry_source_connection_id,
            session_ticket_fetcher=session_ticket_fetcher,
            session_ticket_handler=session_ticket_handler,
            token_handler=token_handler,
        )

    @property
    def gn_pq_established_state(self) -> Optional[GNPQEstablishedState]:
        tls_context = getattr(self, "tls", None)
        if tls_context is None:
            return None
        return cast(Optional[GNPQEstablishedState], getattr(tls_context, "_gn_pq_established", None))

    def _initialize(self, peer_cid: bytes) -> None:
        super()._initialize(peer_cid)

        _gn_pq_log(
            f"quic initialize is_client={self._is_client} peer_cid={_format_cid(peer_cid)} "
            f"host_cid={_format_cid(getattr(self, 'host_cid', None))} "
            f"odcid={_format_cid(getattr(self, 'original_destination_connection_id', None))} "
            f"client_settings={self._gn_pq_client_settings is not None} server_settings={self._gn_pq_server_settings is not None}"
        )

        _install_gn_pq_tls_hooks(
            self.tls,
            quic_connection=self,
            client_settings=self._gn_pq_client_settings,
            server_settings=self._gn_pq_server_settings,
        )

        if self._gn_pq_client_settings is not None:
            client_state: GNPQClientHandshakeState = build_client_handshake()
            self.tls._gn_pq_client_state = client_state
            client_hello_bytes = client_state.client_hello.to_bytes()
            self.tls.handshake_extensions.append(
                (
                    GN_PQ_CLIENT_HELLO_EXTENSION_TYPE,
                    client_hello_bytes,
                )
            )
            _gn_pq_log(
                "client prepared GN PQ hello "
                f"server_domain={self._gn_pq_client_settings.server_domain!r} len={len(client_hello_bytes)}"
            )


class GNQuicServer(AioQuicServer):
    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        create_protocol: Callable = QuicConnectionProtocol,
        session_ticket_fetcher: Optional[tls.SessionTicketFetcher] = None,
        session_ticket_handler: Optional[tls.SessionTicketHandler] = None,
        retry: bool = False,
        stream_handler: Optional[QuicStreamHandler] = None,
        gn_pq_server_settings: Optional[GNQuicServerSettings] = None,
    ) -> None:
        super().__init__(
            configuration=configuration,
            create_protocol=create_protocol,
            session_ticket_fetcher=session_ticket_fetcher,
            session_ticket_handler=session_ticket_handler,
            retry=retry,
            stream_handler=stream_handler,
        )
        self._gn_pq_server_settings = gn_pq_server_settings

    def datagram_received(self, data: Union[bytes, Text], addr: NetworkAddress) -> None:
        data = cast(bytes, data)
        buf = Buffer(data=data)

        try:
            header = pull_quic_header(
                buf, host_cid_length=self._configuration.connection_id_length
            )
        except ValueError:
            return

        if (
            header.version is not None
            and header.version not in self._configuration.supported_versions
        ):
            self._transport.sendto(
                encode_quic_version_negotiation(
                    source_cid=header.destination_cid,
                    destination_cid=header.source_cid,
                    supported_versions=self._configuration.supported_versions,
                ),
                addr,
            )
            return

        protocol = self._protocols.get(header.destination_cid, None)
        original_destination_connection_id: Optional[bytes] = None
        retry_source_connection_id: Optional[bytes] = None
        if (
            protocol is None
            and len(data) >= quic_configuration.SMALLEST_MAX_DATAGRAM_SIZE
            and header.packet_type == QuicPacketType.INITIAL
        ):
            if self._retry is not None:
                if not header.token:
                    version = header.version
                    if version is None:
                        return
                    source_cid = os.urandom(8)
                    self._transport.sendto(
                        encode_quic_retry(
                            version=version,
                            source_cid=source_cid,
                            destination_cid=header.source_cid,
                            original_destination_cid=header.destination_cid,
                            retry_token=self._retry.create_token(
                                addr, header.destination_cid, source_cid
                            ),
                        ),
                        addr,
                    )
                    return
                else:
                    try:
                        (
                            original_destination_connection_id,
                            retry_source_connection_id,
                        ) = self._retry.validate_token(addr, header.token)
                    except ValueError:
                        return
            else:
                original_destination_connection_id = header.destination_cid

            connection = GNQuicConnection(
                configuration=self._configuration,
                original_destination_connection_id=original_destination_connection_id,
                retry_source_connection_id=retry_source_connection_id,
                session_ticket_fetcher=self._session_ticket_fetcher,
                session_ticket_handler=self._session_ticket_handler,
                gn_pq_server_settings=self._gn_pq_server_settings,
            )
            _gn_pq_log(
                f"server created protocol addr={addr} packet_len={len(data)} "
                f"header_type={header.packet_type.name.lower()} dcid={_format_cid(header.destination_cid)} "
                f"scid={_format_cid(header.source_cid)} odcid={_format_cid(original_destination_connection_id)} "
                f"host_cid={_format_cid(connection.host_cid)}"
            )
            protocol = self._create_protocol(
                connection, stream_handler=self._stream_handler
            )
            protocol.connection_made(self._transport)

            protocol._connection_id_issued_handler = partial(
                self._connection_id_issued, protocol=protocol
            )
            protocol._connection_id_retired_handler = partial(
                self._connection_id_retired, protocol=protocol
            )
            protocol._connection_terminated_handler = partial(
                self._connection_terminated, protocol=protocol
            )

            self._protocols[header.destination_cid] = protocol
            self._protocols[connection.host_cid] = protocol

        if protocol is not None:
            protocol.datagram_received(data, addr)