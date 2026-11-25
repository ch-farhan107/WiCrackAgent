"""Encrypted results vault (Fernet AES + PBKDF2-derived key)."""

from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from loguru import logger

_PBKDF2_ITERATIONS = 480_000


def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def _get_salt(salt_path: Path) -> bytes:
    if salt_path.exists():
        return salt_path.read_bytes()
    salt = secrets.token_bytes(16)
    salt_path.parent.mkdir(parents=True, exist_ok=True)
    salt_path.write_bytes(salt)
    return salt


def encrypt_store(store, settings, master_password: str) -> Path:
    """Serialize all results and write an encrypted vault file."""
    rows = [dict(r) for r in store.all_results()]
    payload = json.dumps(rows).encode("utf-8")
    salt = _get_salt(settings.data_dir / "vault.salt")
    token = Fernet(_derive_key(master_password, salt)).encrypt(payload)
    vault_path = settings.data_dir / "vault.bin"
    vault_path.write_bytes(token)
    logger.success("Vault written: {} ({} result(s) encrypted)", vault_path, len(rows))
    return vault_path


def read_vault(vault_path: Path, salt_path: Path, master_password: str) -> list[dict]:
    """Decrypt a vault file; raises ValueError on wrong password/corruption."""
    salt = _get_salt(salt_path)
    try:
        payload = Fernet(_derive_key(master_password, salt)).decrypt(vault_path.read_bytes())
    except InvalidToken as exc:
        raise ValueError("Wrong master password or corrupted vault") from exc
    return list(json.loads(payload))
