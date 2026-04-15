from __future__ import annotations

import datetime
import os
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
    build_client_handshake,
    build_server_handshake,
    complete_client_handshake,
    complete_server_handshake,
    normalize_gn_pq_signature_algorithm_name,
)
from ._gn_pq_session import (
    GNPQClientFinish,
    GNPQClientHello,
    GNPQServerCertificate,
    GNPQServerHello,
)

GN_PQ_CLIENT_HELLO_EXTENSION_TYPE = 0xFF80
GN_PQ_SERVER_HELLO_EXTENSION_TYPE = 0xFF81


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

        public_keys[normalize_gn_pq_signature_algorithm_name(algorithm_name)] = _decode_user_friendly_bytes(
            algorithm_data["pub"]
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

        private_keys[normalize_gn_pq_signature_algorithm_name(algorithm_name)] = _decode_user_friendly_bytes(
            algorithm_data["priv"]
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

    return GNPQServerCertificate(
        center_domain=center_domain,
        center_key_version=center_key_version,
        name=server_domain,
        public_keys=_parse_crt_public_keys(crt_data),
        expires_at=expires_at,
        signature=_decode_user_friendly_bytes(signature),
    )


def build_gn_pq_client_settings(server_domain: str, kdc_key: Optional[bytes] = None) -> Optional[GNQuicClientSettings]:
    if not has_gn_pq_ca_public_keys():
        return None

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
    if not isinstance(kdc, dict):
        raise ValueError("gn_server_crt.crypto.kdc must be a dict")

    if "key" not in kdc:
        raise ValueError("gn_server_crt.crypto.kdc.key is required")

    certificate = _parse_server_certificate(crt_container)
    if certificate.name != server_domain:
        raise ValueError("gn_server_crt.domain must match gn_server_crt.crypto.crt.data.domain")

    kdc_key = _decode_user_friendly_bytes(kdc["key"])

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


def _gn_pq_client_handle_encrypted_extensions(self: tls.Context, input_buf: Buffer) -> None:
    tls.Context._client_handle_encrypted_extensions(self, input_buf)

    settings = getattr(self, "_gn_pq_client_settings", None)
    if settings is None:
        return

    server_hello_payload = _find_extension(self.received_extensions, GN_PQ_SERVER_HELLO_EXTENSION_TYPE)
    if server_hello_payload is None:
        return

    try:
        self._gn_pq_server_hello = GNPQServerHello.from_bytes(server_hello_payload)
    except Exception as exc:
        raise tls.AlertDecodeError("Invalid GN PQ server hello") from exc


def _gn_pq_client_handle_finished(self: tls.Context, input_buf: Buffer, output_buf: Buffer) -> None:
    settings = getattr(self, "_gn_pq_client_settings", None)
    server_hello = getattr(self, "_gn_pq_server_hello", None)
    client_state = getattr(self, "_gn_pq_client_state", None)

    if settings is None or server_hello is None or client_state is None:
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
        raise tls.AlertHandshakeFailure("GN PQ handshake requires a client certificate flight")

    ca_public_key = get_gn_pq_ca_public_key(
        server_hello.server_certificate.center_domain,
        server_hello.server_certificate.center_key_version,
    )
    if ca_public_key is None:
        raise tls.AlertBadCertificate(
            "Unknown GN PQ CA key "
            f"{server_hello.server_certificate.center_domain}"
            f"#{server_hello.server_certificate.center_key_version}"
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
        raise tls.AlertHandshakeFailure("GN PQ client completion failed") from exc

    self._gn_pq_client_completion = completion
    self._gn_pq_established = completion.established

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
        tls.Context._server_handle_hello(self, input_buf, initial_buf, handshake_buf, onertt_buf)
        return

    peer_hello = tls.pull_client_hello(Buffer(data=input_buf.data_slice(0, input_buf.capacity)))
    client_hello_payload = _find_extension(peer_hello.other_extensions, GN_PQ_CLIENT_HELLO_EXTENSION_TYPE)
    if client_hello_payload is None:
        tls.Context._server_handle_hello(self, input_buf, initial_buf, handshake_buf, onertt_buf)
        return

    try:
        client_hello = GNPQClientHello.from_bytes(client_hello_payload)
        server_state = build_server_handshake(
            local_server_domain=settings.server_domain,
            server_identity=settings.server_identity,
            client_hello=client_hello,
        )
    except Exception as exc:
        raise tls.AlertHandshakeFailure("GN PQ server handshake build failed") from exc

    original_extensions = list(self.handshake_extensions)
    original_request_certificate = self._request_client_certificate

    self._gn_pq_server_state = server_state
    self.handshake_extensions = [
        *original_extensions,
        (GN_PQ_SERVER_HELLO_EXTENSION_TYPE, server_state.server_hello.to_bytes()),
    ]
    self._request_client_certificate = True

    try:
        tls.Context._server_handle_hello(self, input_buf, initial_buf, handshake_buf, onertt_buf)
    finally:
        self.handshake_extensions = original_extensions
        self._request_client_certificate = original_request_certificate


def _gn_pq_server_handle_certificate(self: tls.Context, input_buf: Buffer, output_buf: Buffer) -> None:
    settings = getattr(self, "_gn_pq_server_settings", None)
    server_state = getattr(self, "_gn_pq_server_state", None)

    if settings is None or server_state is None:
        tls.Context._server_handle_certificate(self, input_buf, output_buf)
        return

    certificate = tls.pull_certificate(input_buf)
    self.key_schedule.update_hash(input_buf.data)

    if not certificate.certificates:
        raise tls.AlertHandshakeFailure("Missing GN PQ client finish payload")

    certificate_data, certificate_extensions = certificate.certificates[0]
    if certificate_data != b"":
        raise tls.AlertIllegalParameter("GN PQ client finish must not carry an X.509 certificate")

    effective_kdc_key = settings.kdc_key
    server_kdc_key_fetcher = getattr(self, "_gn_pq_server_kdc_key_fetcher", None)
    if server_kdc_key_fetcher is not None:
        try:
            fetched_kdc_key = server_kdc_key_fetcher()
        except Exception as exc:
            raise tls.AlertInternalError("GN PQ server KDC key fetch failed") from exc

        if fetched_kdc_key is not None:
            effective_kdc_key = fetched_kdc_key

    try:
        client_finish = GNPQClientFinish.from_bytes(certificate_extensions)
        established: GNPQEstablishedState = complete_server_handshake(
            local_server_domain=settings.server_domain,
            server_state=server_state,
            client_finish=client_finish,
            kdc_key=effective_kdc_key,
        )
    except Exception as exc:
        raise tls.AlertHandshakeFailure("GN PQ server completion failed") from exc

    self._gn_pq_established = established
    self._server_expect_finished(output_buf)


def _install_gn_pq_tls_hooks(
    context: tls.Context,
    *,
    client_settings: Optional[GNQuicClientSettings],
    server_settings: Optional[GNQuicServerSettings],
    server_kdc_key_fetcher: Optional[Callable[[], Optional[bytes]]] = None,
) -> None:
    context._gn_pq_client_settings = client_settings
    context._gn_pq_server_settings = server_settings
    context._gn_pq_client_state = None
    context._gn_pq_server_state = None
    context._gn_pq_server_hello = None
    context._gn_pq_established = None
    context._gn_pq_client_completion = None
    context._gn_pq_server_kdc_key_fetcher = server_kdc_key_fetcher

    context._client_handle_encrypted_extensions = MethodType(_gn_pq_client_handle_encrypted_extensions, context)
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

        _install_gn_pq_tls_hooks(
            self.tls,
            client_settings=self._gn_pq_client_settings,
            server_settings=self._gn_pq_server_settings,
            server_kdc_key_fetcher=getattr(self, "_gn_pq_server_kdc_key_fetcher", None),
        )

        if self._gn_pq_client_settings is not None:
            client_state: GNPQClientHandshakeState = build_client_handshake()
            self.tls._gn_pq_client_state = client_state
            self.tls.handshake_extensions.append(
                (
                    GN_PQ_CLIENT_HELLO_EXTENSION_TYPE,
                    client_state.client_hello.to_bytes(),
                )
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