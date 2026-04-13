from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Final, Optional

from KeyisBTools.models.serialization import deserialize, serialize
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

GN_PQ_KEM_ALGORITHM: Final[str] = "ML-KEM-1024"
GN_PQ_SIGNATURE_ALGORITHM: Final[str] = "Dilithium5"

GN_NONCE_LEN: Final[int] = 32
GN_X25519_PUBLIC_KEY_LEN: Final[int] = 32
GN_TRANSCRIPT_HASH_LEN: Final[int] = 64
GN_SESSION_ROOT64_LEN: Final[int] = 64
GN_COMMIT_TAG_LEN: Final[int] = 32
GN_U64_LEN: Final[int] = 8

_DOMAIN_BINDING_INFO: Final[bytes] = b"gn:pq:domain-binding:v1"
_TRANSCRIPT_HASH_INFO: Final[bytes] = b"gn:pq:transcript:v1"
_KDC_MIX_INFO: Final[bytes] = b"gn:pq:kdc-mix:v1"
_SESSION_ROOT_INFO: Final[bytes] = b"gn:pq:session-root:v1"
_CERTIFICATE_SIGNATURE_CONTEXT: Final[bytes] = b"gn:pq:cert-sign:v1"
_SERVER_SIGNATURE_CONTEXT: Final[bytes] = b"gn:pq:s1-sign:v2"
_TRANSPORT_KEYS_INFO: Final[bytes] = b"gn:DgEncryptor:root64:v1"
_COMMIT_TAG_INFO: Final[bytes] = b"gn:pq:commit:v1"


def _sha3_512(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA3_512())
    h.update(data)
    return h.finalize()


def _hkdf_sha3_512(key_material: bytes, *, length: int, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA3_512(),
        length=length,
        salt=salt,
        info=info,
    ).derive(key_material)


def _encode_blob(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("Blob is too large to encode")
    return len(value).to_bytes(2, "big") + value


def _decode_blob(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("Malformed blob length")

    length = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2

    end = offset + length
    if end > len(data):
        raise ValueError("Malformed blob body")

    return data[offset:end], end


def _encode_text(value: str) -> bytes:
    return _encode_blob(value.encode("utf-8"))


def _decode_text(data: bytes, offset: int) -> tuple[str, int]:
    value, offset = _decode_blob(data, offset)
    return value.decode("utf-8"), offset


def _encode_u64(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Integer must fit into unsigned 64-bit range")
    return value.to_bytes(GN_U64_LEN, "big")


def _decode_u64(data: bytes, offset: int) -> tuple[int, int]:
    end = offset + GN_U64_LEN
    if end > len(data):
        raise ValueError("Malformed u64 field")
    return int.from_bytes(data[offset:end], "big"), end


def build_domain_binding(domain: str) -> bytes:
    return _hkdf_sha3_512(
        domain.encode("utf-8"),
        length=GN_TRANSCRIPT_HASH_LEN,
        salt=b"",
        info=_DOMAIN_BINDING_INFO,
    )


def _normalize_datetime(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


@dataclass(slots=True)
class GNPQServerCertificate:
    center_domain: str
    center_key_version: int
    name: str
    public_keys: dict[str, bytes]
    expires_at: datetime.datetime
    signature: bytes

    def __post_init__(self) -> None:
        if not self.center_domain:
            raise ValueError("center_domain must not be empty")
        if self.center_key_version < 0:
            raise ValueError("center_key_version must not be negative")
        if not self.name:
            raise ValueError("name must not be empty")
        if not isinstance(self.expires_at, datetime.datetime):
            raise TypeError("expires_at must be datetime.datetime")
        self.expires_at = _normalize_datetime(self.expires_at)

        normalized_public_keys: dict[str, bytes] = {}
        for algorithm, public_key in self.public_keys.items():
            if not algorithm:
                raise ValueError("algorithm name must not be empty")
            if not isinstance(public_key, (bytes, bytearray)):
                raise TypeError("public key must be bytes")
            public_key_bytes = bytes(public_key)
            if not public_key_bytes:
                raise ValueError("public key must not be empty")
            normalized_public_keys[str(algorithm)] = public_key_bytes
        if not normalized_public_keys:
            raise ValueError("public_keys must not be empty")
        self.public_keys = normalized_public_keys

        if not isinstance(self.signature, (bytes, bytearray)):
            raise TypeError("signature must be bytes")
        self.signature = bytes(self.signature)

    def get_public_key(self, algorithm: str) -> bytes:
        if algorithm not in self.public_keys:
            raise ValueError(f"Server certificate does not contain algorithm {algorithm!r}")
        return self.public_keys[algorithm]

    def data_dict(self) -> dict[str, Any]:
        return {
            "c": self.center_domain,
            "c_v": self.center_key_version,
            "domain": self.name,
            "algs": {
                algorithm: {"pub": public_key}
                for algorithm, public_key in self.public_keys.items()
            },
            "exp": self.expires_at,
        }

    def unsigned_bytes(self) -> bytes:
        return serialize(self.data_dict())

    def to_bytes(self) -> bytes:
        return serialize({
            "data": self.data_dict(),
            "sign": self.signature,
        })

    @classmethod
    def from_dict(cls, value: Any) -> GNPQServerCertificate:
        if not isinstance(value, dict):
            raise ValueError("ServerCertificate payload must be a dict")

        data = value.get("data")
        signature = value.get("sign")
        if not isinstance(data, dict):
            raise ValueError("ServerCertificate data must be a dict")
        if not isinstance(signature, (bytes, bytearray)):
            raise ValueError("ServerCertificate sign must be bytes")

        center_domain = data.get("c")
        center_key_version = data.get("c_v")
        name = data.get("domain")
        algs = data.get("algs")
        expires_at = data.get("exp")

        if not isinstance(center_domain, str) or not center_domain:
            raise ValueError("ServerCertificate data.c must be a non-empty string")
        if not isinstance(center_key_version, int) or center_key_version < 0:
            raise ValueError("ServerCertificate data.c_v must be a non-negative int")
        if not isinstance(name, str) or not name:
            raise ValueError("ServerCertificate data.domain must be a non-empty string")
        if not isinstance(algs, dict) or not algs:
            raise ValueError("ServerCertificate data.algs must be a non-empty dict")
        if not isinstance(expires_at, datetime.datetime):
            raise ValueError("ServerCertificate data.exp must be datetime.datetime")

        public_keys: dict[str, bytes] = {}
        for algorithm, alg_value in algs.items():
            if not isinstance(algorithm, str) or not algorithm:
                raise ValueError("ServerCertificate algorithm name must be a non-empty string")
            if not isinstance(alg_value, dict):
                raise ValueError("ServerCertificate algorithm payload must be a dict")

            public_key = alg_value.get("pub")
            if not isinstance(public_key, (bytes, bytearray)):
                raise ValueError("ServerCertificate algorithm pub must be bytes")
            public_keys[algorithm] = bytes(public_key)

        return cls(
            center_domain=center_domain,
            center_key_version=center_key_version,
            name=name,
            public_keys=public_keys,
            expires_at=expires_at,
            signature=bytes(signature),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> GNPQServerCertificate:
        return cls.from_dict(deserialize(data))


@dataclass(slots=True)
class GNPQClientHello:
    client_nonce: bytes
    client_x25519_public_key: bytes

    def __post_init__(self) -> None:
        if len(self.client_nonce) != GN_NONCE_LEN:
            raise ValueError("client_nonce must be 32 bytes")
        if len(self.client_x25519_public_key) != GN_X25519_PUBLIC_KEY_LEN:
            raise ValueError("client_x25519_public_key must be 32 bytes")

    def to_bytes(self) -> bytes:
        return self.client_nonce + self.client_x25519_public_key

    @classmethod
    def from_bytes(cls, data: bytes) -> GNPQClientHello:
        expected_len = GN_NONCE_LEN + GN_X25519_PUBLIC_KEY_LEN
        if len(data) != expected_len:
            raise ValueError("ClientHello payload is too short")

        return cls(
            client_nonce=data[:GN_NONCE_LEN],
            client_x25519_public_key=data[GN_NONCE_LEN:],
        )


@dataclass(slots=True)
class GNPQServerHello:
    server_nonce: bytes
    server_x25519_public_key: bytes
    server_ml_kem_public_key: bytes
    signature_algorithm: str
    server_certificate: GNPQServerCertificate
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.server_nonce) != GN_NONCE_LEN:
            raise ValueError("server_nonce must be 32 bytes")
        if len(self.server_x25519_public_key) != GN_X25519_PUBLIC_KEY_LEN:
            raise ValueError("server_x25519_public_key must be 32 bytes")
        if not self.server_ml_kem_public_key:
            raise ValueError("server_ml_kem_public_key must not be empty")
        if not self.signature_algorithm:
            raise ValueError("signature_algorithm must not be empty")

    def unsigned_bytes(self) -> bytes:
        return (
            self.server_nonce
            + self.server_x25519_public_key
            + _encode_blob(self.server_ml_kem_public_key)
            + _encode_text(self.signature_algorithm)
            + _encode_blob(self.server_certificate.to_bytes())
        )

    def to_bytes(self) -> bytes:
        return self.unsigned_bytes() + _encode_blob(self.signature)

    @classmethod
    def from_bytes(cls, data: bytes) -> GNPQServerHello:
        min_len = GN_NONCE_LEN + GN_X25519_PUBLIC_KEY_LEN + 2 + 2 + 2 + 2
        if len(data) < min_len:
            raise ValueError("ServerHello payload is too short")

        offset = 0
        server_nonce = data[offset:offset + GN_NONCE_LEN]
        offset += GN_NONCE_LEN

        server_x25519_public_key = data[offset:offset + GN_X25519_PUBLIC_KEY_LEN]
        offset += GN_X25519_PUBLIC_KEY_LEN

        server_ml_kem_public_key, offset = _decode_blob(data, offset)
        signature_algorithm, offset = _decode_text(data, offset)
        certificate_bytes, offset = _decode_blob(data, offset)
        server_certificate = GNPQServerCertificate.from_bytes(certificate_bytes)

        signature, offset = _decode_blob(data, offset)
        if offset != len(data):
            raise ValueError("Unexpected trailing bytes in ServerHello payload")

        return cls(
            server_nonce=server_nonce,
            server_x25519_public_key=server_x25519_public_key,
            server_ml_kem_public_key=server_ml_kem_public_key,
            signature_algorithm=signature_algorithm,
            server_certificate=server_certificate,
            signature=signature,
        )


@dataclass(slots=True)
class GNPQClientFinish:
    ml_kem_ciphertext: bytes

    def __post_init__(self) -> None:
        if not self.ml_kem_ciphertext:
            raise ValueError("ml_kem_ciphertext must not be empty")

    def to_bytes(self) -> bytes:
        return _encode_blob(self.ml_kem_ciphertext)

    @classmethod
    def from_bytes(cls, data: bytes) -> GNPQClientFinish:
        ml_kem_ciphertext, offset = _decode_blob(data, 0)
        if offset != len(data):
            raise ValueError("Unexpected trailing bytes in ClientFinish payload")
        return cls(ml_kem_ciphertext=ml_kem_ciphertext)


@dataclass(slots=True)
class GNPQCommit:
    transcript_hash: bytes
    commit_tag: bytes

    def __post_init__(self) -> None:
        if len(self.transcript_hash) != GN_TRANSCRIPT_HASH_LEN:
            raise ValueError("transcript_hash must be 64 bytes")
        if len(self.commit_tag) != GN_COMMIT_TAG_LEN:
            raise ValueError("commit_tag must be 32 bytes")

    def to_bytes(self) -> bytes:
        return self.transcript_hash + self.commit_tag

    @classmethod
    def from_bytes(cls, data: bytes) -> GNPQCommit:
        expected_len = GN_TRANSCRIPT_HASH_LEN + GN_COMMIT_TAG_LEN
        if len(data) != expected_len:
            raise ValueError("Commit payload has invalid length")
        return cls(
            transcript_hash=data[:GN_TRANSCRIPT_HASH_LEN],
            commit_tag=data[GN_TRANSCRIPT_HASH_LEN:],
        )


def build_transcript_hash(local_server_domain: str, *handshake_payloads: bytes) -> bytes:
    domain_binding = build_domain_binding(local_server_domain)
    transcript = domain_binding
    for payload in handshake_payloads:
        transcript += _encode_blob(payload)
    return _hkdf_sha3_512(transcript, length=GN_TRANSCRIPT_HASH_LEN, salt=b"", info=_TRANSCRIPT_HASH_INFO)


def build_certificate_signature_message(certificate_unsigned: bytes) -> bytes:
    return _CERTIFICATE_SIGNATURE_CONTEXT + _sha3_512(certificate_unsigned)


def build_server_signature_message(local_server_domain: str, client_hello_payload: bytes, server_hello_unsigned: bytes) -> bytes:
    return (
        _SERVER_SIGNATURE_CONTEXT
        + build_domain_binding(local_server_domain)
        + _sha3_512(client_hello_payload)
        + _sha3_512(server_hello_unsigned)
    )


def derive_kdc_mix(
    kdc_key: Optional[bytes],
    *,
    local_server_domain: str,
    client_nonce: bytes,
    server_nonce: bytes,
) -> bytes:
    if kdc_key is None:
        return bytes(GN_SESSION_ROOT64_LEN)

    if len(client_nonce) != GN_NONCE_LEN or len(server_nonce) != GN_NONCE_LEN:
        raise ValueError("Invalid nonce length for KDC mix")

    salt = build_domain_binding(local_server_domain) + client_nonce + server_nonce
    return _hkdf_sha3_512(kdc_key, length=GN_SESSION_ROOT64_LEN, salt=salt, info=_KDC_MIX_INFO)


def derive_session_root64(
    *,
    local_server_domain: str,
    client_nonce: bytes,
    server_nonce: bytes,
    ml_kem_shared_secret: bytes,
    x25519_shared_secret: bytes,
    transcript_hash: bytes,
    kdc_key: Optional[bytes] = None,
) -> bytes:
    if len(client_nonce) != GN_NONCE_LEN or len(server_nonce) != GN_NONCE_LEN:
        raise ValueError("Invalid nonce length for root64 derivation")
    if len(transcript_hash) != GN_TRANSCRIPT_HASH_LEN:
        raise ValueError("transcript_hash must be 64 bytes")

    kdc_mix = derive_kdc_mix(
        kdc_key,
        local_server_domain=local_server_domain,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
    )
    salt = build_domain_binding(local_server_domain) + client_nonce + server_nonce
    key_material = ml_kem_shared_secret + x25519_shared_secret + kdc_mix + transcript_hash
    return _hkdf_sha3_512(key_material, length=GN_SESSION_ROOT64_LEN, salt=salt, info=_SESSION_ROOT_INFO)


def derive_transport_keys_from_root64(root64: bytes, *, local_domain: str, peer_domain: str) -> tuple[bytes, bytes]:
    if len(root64) != GN_SESSION_ROOT64_LEN:
        raise ValueError("root64 must be exactly 64 bytes")

    key_in = _hkdf_sha3_512(
        root64,
        length=32,
        salt=peer_domain.encode("utf-8") + local_domain.encode("utf-8"),
        info=_TRANSPORT_KEYS_INFO,
    )
    key_out = _hkdf_sha3_512(
        root64,
        length=32,
        salt=local_domain.encode("utf-8") + peer_domain.encode("utf-8"),
        info=_TRANSPORT_KEYS_INFO,
    )
    return key_in, key_out


def build_commit_payload(root64: bytes, transcript_hash: bytes) -> GNPQCommit:
    if len(root64) != GN_SESSION_ROOT64_LEN:
        raise ValueError("root64 must be exactly 64 bytes")
    if len(transcript_hash) != GN_TRANSCRIPT_HASH_LEN:
        raise ValueError("transcript_hash must be 64 bytes")

    commit_tag = _hkdf_sha3_512(root64, length=GN_COMMIT_TAG_LEN, salt=transcript_hash, info=_COMMIT_TAG_INFO)
    return GNPQCommit(transcript_hash=transcript_hash, commit_tag=commit_tag)


def verify_commit_payload(root64: bytes, commit: GNPQCommit) -> bool:
    expected = build_commit_payload(root64, commit.transcript_hash)
    return expected.commit_tag == commit.commit_tag