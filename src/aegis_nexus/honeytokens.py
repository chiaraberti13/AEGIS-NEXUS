from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class HoneytokenCredential:
    username: str
    password: str
    password_sha256: str
    token_id: str


def honeytoken_credential() -> HoneytokenCredential | None:
    seed = os.getenv("AEGIS_HONEYTOKEN_SEED", "").strip()
    if not seed:
        return None
    bounded_seed = seed[:512]
    digest = hashlib.sha256(("aegis-honeytoken-v1:" + bounded_seed).encode("utf-8", "replace")).hexdigest()
    username = f"svc_backup_{digest[:6]}"
    password = f"Mnt!{digest[6:22]}9q"
    return HoneytokenCredential(
        username=username,
        password=password,
        password_sha256=hashlib.sha256(password.encode("utf-8")).hexdigest(),
        token_id="ht_" + digest[22:34],
    )


def honeytoken_descriptor() -> dict[str, str] | None:
    token = honeytoken_credential()
    if token is None:
        return None
    return {
        "token_id": token.token_id,
        "username": token.username,
        "password_sha256": token.password_sha256,
    }
