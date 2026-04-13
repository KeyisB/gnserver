from __future__ import annotations

from typing import Optional

from KeyisBTools.bytes.transformation import userFriendly


# Fill this with userFriendly-encoded ML-DSA CA public key bytes.
# Format: {"@gn": {1: "...", 2: "..."}}
_GN_PQ_CA_PUBS_UF: dict[str, dict[int, str]] = {}


def has_gn_pq_ca_public_keys() -> bool:
    return any(versions for versions in _GN_PQ_CA_PUBS_UF.values())


def get_gn_pq_ca_public_key(center_domain: str, center_key_version: int) -> Optional[bytes]:
    versions = _GN_PQ_CA_PUBS_UF.get(center_domain)
    if versions is None:
        return None

    value = versions.get(center_key_version)
    if not value:
        return None
    return userFriendly.decode(value)