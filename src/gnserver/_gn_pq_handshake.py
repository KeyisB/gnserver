from __future__ import annotations

import datetime
import os
import time
import traceback
from dataclasses import dataclass
from functools import lru_cache
from typing import Final, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._gn_pq_session import (
    GN_NONCE_LEN,
    GN_PQ_KEM_ALGORITHM,
    GN_PQ_SIGNATURE_ALGORITHM,
    GNPQClientFinish,
    GNPQClientHello,
    GNPQCommit,
    GNPQServerCertificate,
    GNPQServerHello,
    build_commit_payload,
    build_certificate_signature_message,
    build_server_signature_message,
    build_transcript_hash,
    derive_session_root64,
    verify_commit_payload,
)
from .oqs import (
    KeyEncapsulation,
    MechanismNotSupportedError,
    Signature,
    get_enabled_kem_mechanisms,
    get_enabled_sig_mechanisms,
)

from KeyisBTools import userFriendly

def _gn_pq_handshake_log(message: str) -> None:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] [GN PQ] {message}")


def _sha3_256_hex(data: bytes) -> str:
    h = hashes.Hash(hashes.SHA3_256())
    h.update(data)
    return h.finalize().hex()


_GN_PQ_KEM_ALIASES: Final[dict[str, str]] = {
    "kyber512": "ml-kem-512",
    "kyber768": "ml-kem-768",
    "kyber1024": "ml-kem-1024",
}

_GN_PQ_SIGNATURE_ALIASES: Final[dict[str, str]] = {
    "dilithium2": "ml-dsa-44",
    "dilithium3": "ml-dsa-65",
    "dilithium5": "ml-dsa-87",
}


def _normalize_gn_pq_algorithm_name(
    algorithm: str,
    *,
    aliases: dict[str, str],
    enabled_algorithms: tuple[str, ...],
) -> str:
    normalized_algorithm = aliases.get(algorithm.casefold(), algorithm.casefold())
    for candidate in enabled_algorithms:
        if candidate.casefold() == normalized_algorithm:
            return normalized_algorithm
    raise MechanismNotSupportedError(algorithm)


def _get_oqs_algorithm_name(normalized_algorithm: str, *, enabled_algorithms: tuple[str, ...]) -> str:
    for candidate in enabled_algorithms:
        if candidate.casefold() == normalized_algorithm:
            return candidate
    raise MechanismNotSupportedError(normalized_algorithm)


@dataclass(slots=True)
class GNPQSignatureKeyMaterial:
    public_key: bytes
    private_key: bytes
    algorithm: str

    @classmethod
    def generate(cls, algorithm: str = GN_PQ_SIGNATURE_ALGORITHM) -> GNPQSignatureKeyMaterial:
        normalized_algorithm = normalize_gn_pq_signature_algorithm_name(algorithm)
        oqs_algorithm = get_oqs_gn_pq_signature_algorithm_name(normalized_algorithm)
        with Signature(oqs_algorithm) as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()

        return cls(
            public_key=public_key,
            private_key=private_key,
            algorithm=normalized_algorithm,
        )


@dataclass(slots=True)
class GNPQCertifiedServerIdentity:
    certificate: GNPQServerCertificate
    private_keys: dict[str, bytes]


def normalize_gn_pq_signature_algorithm_name(algorithm: str) -> str:
    return _normalize_gn_pq_algorithm_name(
        algorithm,
        aliases=_GN_PQ_SIGNATURE_ALIASES,
        enabled_algorithms=get_enabled_sig_mechanisms(),
    )


def get_oqs_gn_pq_signature_algorithm_name(algorithm: str) -> str:
    normalized_algorithm = normalize_gn_pq_signature_algorithm_name(algorithm)
    return _get_oqs_algorithm_name(
        normalized_algorithm,
        enabled_algorithms=get_enabled_sig_mechanisms(),
    )


def normalize_gn_pq_kem_algorithm_name(algorithm: str) -> str:
    return _normalize_gn_pq_algorithm_name(
        algorithm,
        aliases=_GN_PQ_KEM_ALIASES,
        enabled_algorithms=get_enabled_kem_mechanisms(),
    )


def get_oqs_gn_pq_kem_algorithm_name(algorithm: str) -> str:
    normalized_algorithm = normalize_gn_pq_kem_algorithm_name(algorithm)
    return _get_oqs_algorithm_name(
        normalized_algorithm,
        enabled_algorithms=get_enabled_kem_mechanisms(),
    )


def get_default_gn_pq_signature_algorithm_name() -> str:
    return normalize_gn_pq_signature_algorithm_name(GN_PQ_SIGNATURE_ALGORITHM)


@lru_cache(maxsize=None)
def get_gn_pq_signature_artifact_lengths(algorithm: str) -> tuple[int, int, int]:
    normalized_algorithm = normalize_gn_pq_signature_algorithm_name(algorithm)
    oqs_algorithm = get_oqs_gn_pq_signature_algorithm_name(normalized_algorithm)
    with Signature(oqs_algorithm) as sig:
        return (
            int(sig.details["length_public_key"]),
            int(sig.details["length_secret_key"]),
            int(sig.details["length_signature"]),
        )


def issue_server_certificate(
    *,
    center_domain: str,
    center_key_version: int,
    server_name: str,
    server_signing_public_keys: dict[str, bytes],
    ca_private_key: bytes,
    expires_at: datetime.datetime,
    ca_signature_algorithm: str = GN_PQ_SIGNATURE_ALGORITHM,
) -> GNPQServerCertificate:
    normalized_public_keys: dict[str, bytes] = {}
    for algorithm, public_key in server_signing_public_keys.items():
        normalized_public_keys[normalize_gn_pq_signature_algorithm_name(algorithm)] = public_key

    unsigned_certificate = GNPQServerCertificate(
        center_domain=center_domain,
        center_key_version=center_key_version,
        name=server_name,
        public_keys=normalized_public_keys,
        expires_at=expires_at,
        signature=b"",
    )
    certificate_message = build_certificate_signature_message(unsigned_certificate.unsigned_bytes())

    unsigned_fp = _sha3_256_hex(unsigned_certificate.unsigned_bytes())
    msg_fp = _sha3_256_hex(certificate_message)
    _gn_pq_handshake_log(
        f"issue certificate server={server_name!r} "
        f"unsigned_fp={unsigned_fp[:16]} msg_fp={msg_fp[:16]} "
        f"unsigned_len={len(unsigned_certificate.unsigned_bytes())}"
    )

    oqs_ca_signature_algorithm = get_oqs_gn_pq_signature_algorithm_name(ca_signature_algorithm)
    with Signature(oqs_ca_signature_algorithm, secret_key=ca_private_key) as ca_sig:
        signature = ca_sig.sign(certificate_message)

    return GNPQServerCertificate(
        center_domain=center_domain,
        center_key_version=center_key_version,
        name=server_name,
        public_keys=normalized_public_keys,
        expires_at=expires_at,
        signature=signature,
    )


def verify_server_certificate(
    *,
    expected_server_domain: str,
    certificate: GNPQServerCertificate,
    ca_public_key: bytes,
    ca_signature_algorithm: str = GN_PQ_SIGNATURE_ALGORITHM,
    now_timestamp: Optional[datetime.datetime] = None,
) -> None:
    if certificate.name != expected_server_domain:
        raise ValueError("Server certificate name mismatch")

    if now_timestamp is None:
        now_timestamp = datetime.datetime.now(datetime.timezone.utc)
    if now_timestamp.tzinfo is None:
        now_timestamp = now_timestamp.replace(tzinfo=datetime.timezone.utc)
    else:
        now_timestamp = now_timestamp.astimezone(datetime.timezone.utc)
    if now_timestamp > certificate.expires_at:
        raise ValueError("Server certificate expired")

    unsigned_raw = certificate.unsigned_bytes()
    certificate_message = build_certificate_signature_message(unsigned_raw)
    source_data = getattr(certificate, "source_data", None)
    canonical_valid: Optional[bool] = None

    _gn_pq_handshake_log(
        f"verify_server_certificate start server={certificate.name!r} "
        f"ca={certificate.center_domain!r}#{certificate.center_key_version} "
        f"source_data={source_data is not None} "
        f"unsigned_len={len(unsigned_raw)} "
        f"msg_len={len(certificate_message)} msg_eq_unsigned={certificate_message == unsigned_raw} "
        f"sig_len={len(certificate.signature)} "
        f"ca_key_len={len(ca_public_key)} "
        f"unsigned_head={unsigned_raw[:16].hex()} "
        f"msg_head={certificate_message[:16].hex()} "
        f"sig_head={certificate.signature[:16].hex()}"
    )

    oqs_ca_signature_algorithm = get_oqs_gn_pq_signature_algorithm_name(ca_signature_algorithm)
    with Signature(oqs_ca_signature_algorithm) as ca_sig:
        source_valid = ca_sig.verify(certificate_message, certificate.signature, ca_public_key)
        _gn_pq_handshake_log(f"verify_server_certificate source_valid={source_valid}")

        if not source_valid and source_data is not None:
            canonical_certificate = GNPQServerCertificate(
                center_domain=certificate.center_domain,
                center_key_version=certificate.center_key_version,
                name=certificate.name,
                public_keys=certificate.public_keys,
                expires_at=certificate.expires_at,
                signature=certificate.signature,
            )
            canonical_message = build_certificate_signature_message(canonical_certificate.unsigned_bytes())
            canonical_eq = canonical_message == certificate_message
            _gn_pq_handshake_log(
                f"verify_server_certificate canonical check: "
                f"canonical_msg_len={len(canonical_message)} canonical_eq_source={canonical_eq} "
                f"canonical_head={canonical_message[:16].hex()}"
            )
            if not canonical_eq:
                canonical_valid = ca_sig.verify(canonical_message, certificate.signature, ca_public_key)
                _gn_pq_handshake_log(f"verify_server_certificate canonical_valid={canonical_valid}")

        if not source_valid:
            expected_public_key_len, _, expected_signature_len = get_gn_pq_signature_artifact_lengths(
                ca_signature_algorithm
            )
            ca_key_fp = _sha3_256_hex(ca_public_key)
            msg_fp = _sha3_256_hex(certificate_message)
            sig_fp = _sha3_256_hex(certificate.signature)
            unsigned_fp = _sha3_256_hex(unsigned_raw)
            _gn_pq_handshake_log(
                "verify server certificate FAILED "
                f"server={certificate.name!r} ca={certificate.center_domain!r}#{certificate.center_key_version} "
                f"source_data={source_data is not None} canonical_valid={canonical_valid} "
                f"ca_key_len={len(ca_public_key)}/{expected_public_key_len} "
                f"sig_len={len(certificate.signature)}/{expected_signature_len} "
                f"unsigned_len={len(unsigned_raw)} "
                f"ca_key_fp={ca_key_fp[:16]} "
                f"msg_fp={msg_fp[:16]} "
                f"sig_fp={sig_fp[:16]} "
                f"unsigned_fp={unsigned_fp[:16]} "
                f"ca_key_head={ca_public_key[:8].hex()}"
            )
            raise ValueError("Invalid CA signature on server certificate")


@dataclass(slots=True)
class GNPQClientHandshakeState:
    client_hello: GNPQClientHello
    x25519_private_key: X25519PrivateKey


@dataclass(slots=True)
class GNPQServerHandshakeState:
    client_hello: GNPQClientHello
    server_hello: GNPQServerHello
    ml_kem_private_key: bytes
    x25519_shared_secret: bytes


@dataclass(slots=True)
class GNPQEstablishedState:
    transcript_hash: bytes
    root64: bytes

    def build_commit(self) -> GNPQCommit:
        return build_commit_payload(self.root64, self.transcript_hash)

    def verify_commit(self, commit: GNPQCommit) -> bool:
        return verify_commit_payload(self.root64, commit)


@dataclass(slots=True)
class GNPQClientCompletion:
    established: GNPQEstablishedState
    client_finish: GNPQClientFinish
    commit: GNPQCommit


def build_client_handshake() -> GNPQClientHandshakeState:
    x25519_private_key = X25519PrivateKey.generate()
    client_x25519_public_key = x25519_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    client_hello = GNPQClientHello(
        client_nonce=os.urandom(GN_NONCE_LEN),
        client_x25519_public_key=client_x25519_public_key,
    )
    return GNPQClientHandshakeState(
        client_hello=client_hello,
        x25519_private_key=x25519_private_key,
    )


def build_server_handshake(
    *,
    local_server_domain: str,
    server_identity: GNPQCertifiedServerIdentity,
    client_hello: GNPQClientHello,
) -> GNPQServerHandshakeState:
    if server_identity.certificate.name != local_server_domain:
        raise ValueError("Server certificate name does not match local server domain")

    signature_algorithm = get_default_gn_pq_signature_algorithm_name()
    oqs_signature_algorithm = get_oqs_gn_pq_signature_algorithm_name(signature_algorithm)
    if signature_algorithm not in server_identity.private_keys:
        raise ValueError(f"Server identity does not contain private key for {signature_algorithm}")
    server_identity.certificate.get_public_key(signature_algorithm)

    with KeyEncapsulation(get_oqs_gn_pq_kem_algorithm_name(GN_PQ_KEM_ALGORITHM)) as kem:
        ml_kem_public_key = kem.generate_keypair()
        ml_kem_private_key = kem.export_secret_key()

    server_x25519_private_key = X25519PrivateKey.generate()
    server_x25519_public_key = server_x25519_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    client_x25519_public_key = X25519PublicKey.from_public_bytes(client_hello.client_x25519_public_key)
    x25519_shared_secret = server_x25519_private_key.exchange(client_x25519_public_key)

    unsigned_server_hello = GNPQServerHello(
        server_nonce=os.urandom(GN_NONCE_LEN),
        server_x25519_public_key=server_x25519_public_key,
        server_ml_kem_public_key=ml_kem_public_key,
        signature_algorithm=signature_algorithm,
        server_certificate=server_identity.certificate,
        signature=b"",
    )
    signature_message = build_server_signature_message(
        local_server_domain,
        client_hello.to_bytes(),
        unsigned_server_hello.unsigned_bytes(),
    )

    with Signature(oqs_signature_algorithm, secret_key=server_identity.private_keys[signature_algorithm]) as sig:
        signature = sig.sign(signature_message)

    server_hello = GNPQServerHello(
        server_nonce=unsigned_server_hello.server_nonce,
        server_x25519_public_key=unsigned_server_hello.server_x25519_public_key,
        server_ml_kem_public_key=unsigned_server_hello.server_ml_kem_public_key,
        signature_algorithm=unsigned_server_hello.signature_algorithm,
        server_certificate=unsigned_server_hello.server_certificate,
        signature=signature,
    )
    return GNPQServerHandshakeState(
        client_hello=client_hello,
        server_hello=server_hello,
        ml_kem_private_key=ml_kem_private_key,
        x25519_shared_secret=x25519_shared_secret,
    )


def complete_client_handshake(
    *,
    local_server_domain: str,
    client_state: GNPQClientHandshakeState,
    server_hello: GNPQServerHello,
    ca_public_key: bytes,
    ca_signature_algorithm: str = GN_PQ_SIGNATURE_ALGORITHM,
    now_timestamp: Optional[datetime.datetime] = None,
    kdc_key: Optional[bytes] = None,
) -> GNPQClientCompletion:
    _gn_pq_handshake_log(
        f"complete_client_handshake start domain={local_server_domain!r} "
        f"sig_algo={server_hello.signature_algorithm!r} "
        f"kdc_key={'present' if kdc_key else 'none'}"
    )

    _gn_pq_handshake_log("step 1: verify_server_certificate")
    verify_server_certificate(
        expected_server_domain=local_server_domain,
        certificate=server_hello.server_certificate,
        ca_public_key=ca_public_key,
        ca_signature_algorithm=ca_signature_algorithm,
        now_timestamp=now_timestamp,
    )
    _gn_pq_handshake_log("step 1: verify_server_certificate OK")

    _gn_pq_handshake_log("step 2: verify server ML-DSA signature")
    signature_message = build_server_signature_message(
        local_server_domain,
        client_state.client_hello.to_bytes(),
        server_hello.unsigned_bytes(),
    )
    server_public_key = server_hello.server_certificate.get_public_key(server_hello.signature_algorithm)
    with Signature(get_oqs_gn_pq_signature_algorithm_name(server_hello.signature_algorithm)) as sig:
        if not sig.verify(signature_message, server_hello.signature, server_public_key):
            raise ValueError("Invalid server ML-DSA signature in server hello")
    _gn_pq_handshake_log("step 2: verify server ML-DSA signature OK")

    _gn_pq_handshake_log("step 3: X25519 key exchange")
    server_x25519_public_key = X25519PublicKey.from_public_bytes(server_hello.server_x25519_public_key)
    x25519_shared_secret = client_state.x25519_private_key.exchange(server_x25519_public_key)
    _gn_pq_handshake_log("step 3: X25519 key exchange OK")

    _gn_pq_handshake_log("step 4: ML-KEM encapsulation")
    with KeyEncapsulation(get_oqs_gn_pq_kem_algorithm_name(GN_PQ_KEM_ALGORITHM)) as kem:
        ml_kem_ciphertext, ml_kem_shared_secret = kem.encap_secret(server_hello.server_ml_kem_public_key)
    _gn_pq_handshake_log("step 4: ML-KEM encapsulation OK")

    _gn_pq_handshake_log("step 5: derive session root")
    client_finish = GNPQClientFinish(ml_kem_ciphertext=ml_kem_ciphertext)
    ch_bytes = client_state.client_hello.to_bytes()
    sh_bytes = server_hello.to_bytes()
    cf_bytes = client_finish.to_bytes()
    transcript_hash = build_transcript_hash(
        local_server_domain,
        ch_bytes,
        sh_bytes,
        cf_bytes,
    )
    root64 = derive_session_root64(
        local_server_domain=local_server_domain,
        client_nonce=client_state.client_hello.client_nonce,
        server_nonce=server_hello.server_nonce,
        ml_kem_shared_secret=ml_kem_shared_secret,
        x25519_shared_secret=x25519_shared_secret,
        transcript_hash=transcript_hash,
        kdc_key=kdc_key,
    )
    import hashlib
    _gn_pq_handshake_log(
        f"step 5: derive session root OK "
        f"transcript_fp={hashlib.sha3_256(transcript_hash).hexdigest()[:16]} "
        f"root64_fp={hashlib.sha3_256(root64).hexdigest()[:16]} "
        f"ch_len={len(ch_bytes)} sh_len={len(sh_bytes)} cf_len={len(cf_bytes)} "
        f"ch_fp={hashlib.sha3_256(ch_bytes).hexdigest()[:16]} "
        f"sh_fp={hashlib.sha3_256(sh_bytes).hexdigest()[:16]} "
        f"cf_fp={hashlib.sha3_256(cf_bytes).hexdigest()[:16]} "
        f"mlkem_ss_fp={hashlib.sha3_256(ml_kem_shared_secret).hexdigest()[:16]} "
        f"x25519_ss_fp={hashlib.sha3_256(x25519_shared_secret).hexdigest()[:16]} "
        f"kdc_key_fp={kdc_key.hex() if kdc_key else 'none'} "
        f"kdc_key={kdc_key if kdc_key else 'none'} "
        f"kdc_key_uf={userFriendly.encode(kdc_key) if kdc_key else 'none'}"
    )

    established = GNPQEstablishedState(transcript_hash=transcript_hash, root64=root64)
    return GNPQClientCompletion(
        established=established,
        client_finish=client_finish,
        commit=established.build_commit(),
    )


def complete_server_handshake(
    *,
    local_server_domain: str,
    server_state: GNPQServerHandshakeState,
    client_finish: GNPQClientFinish,
    kdc_key: Optional[bytes] = None,
) -> GNPQEstablishedState:
    with KeyEncapsulation(
        get_oqs_gn_pq_kem_algorithm_name(GN_PQ_KEM_ALGORITHM),
        secret_key=server_state.ml_kem_private_key,
    ) as kem:
        ml_kem_shared_secret = kem.decap_secret(client_finish.ml_kem_ciphertext)

    ch_bytes = server_state.client_hello.to_bytes()
    sh_bytes = server_state.server_hello.to_bytes()
    cf_bytes = client_finish.to_bytes()
    transcript_hash = build_transcript_hash(
        local_server_domain,
        ch_bytes,
        sh_bytes,
        cf_bytes,
    )
    root64 = derive_session_root64(
        local_server_domain=local_server_domain,
        client_nonce=server_state.client_hello.client_nonce,
        server_nonce=server_state.server_hello.server_nonce,
        ml_kem_shared_secret=ml_kem_shared_secret,
        x25519_shared_secret=server_state.x25519_shared_secret,
        transcript_hash=transcript_hash,
        kdc_key=kdc_key,
    )
    import hashlib
    _gn_pq_handshake_log(
        f"server complete_server_handshake "
        f"transcript_fp={hashlib.sha3_256(transcript_hash).hexdigest()[:16]} "
        f"root64_fp={hashlib.sha3_256(root64).hexdigest()[:16]} "
        f"ch_len={len(ch_bytes)} sh_len={len(sh_bytes)} cf_len={len(cf_bytes)} "
        f"ch_fp={hashlib.sha3_256(ch_bytes).hexdigest()[:16]} "
        f"sh_fp={hashlib.sha3_256(sh_bytes).hexdigest()[:16]} "
        f"cf_fp={hashlib.sha3_256(cf_bytes).hexdigest()[:16]} "
        f"mlkem_ss_fp={hashlib.sha3_256(ml_kem_shared_secret).hexdigest()[:16]} "
        f"x25519_ss_fp={hashlib.sha3_256(server_state.x25519_shared_secret).hexdigest()[:16]} "
        f"kdc_key_fp={kdc_key.hex() if kdc_key else 'none'} "
        f"kdc_key={kdc_key if kdc_key else 'none'} "
        f"kdc_key_uf={userFriendly.encode(kdc_key) if kdc_key else 'none'}"
    )
    return GNPQEstablishedState(transcript_hash=transcript_hash, root64=root64)