from __future__ import annotations

import hashlib
import io
import re
import secrets
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.files.base import ContentFile

TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


@dataclass(frozen=True)
class IssuedToken:
    raw: str
    digest: str


def issue_upload_token() -> IssuedToken:
    raw = secrets.token_urlsafe(32)
    return IssuedToken(raw=raw, digest=hash_upload_token(raw))


def hash_upload_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def is_well_formed_token(raw_token: str) -> bool:
    return bool(TOKEN_PATTERN.fullmatch(raw_token))


def consume_token_digest() -> str:
    """Return an unreachable random digest after a single-use link is consumed."""
    return hashlib.sha256(secrets.token_bytes(64)).hexdigest()


def _fernet() -> MultiFernet:
    return MultiFernet(
        [Fernet(key.encode("ascii")) for key in settings.FILE_ENCRYPTION_KEYS]
    )


def encrypt_bytes(plain_bytes: bytes) -> ContentFile:
    return ContentFile(_fernet().encrypt(plain_bytes))


def decrypt_bytes(encrypted_bytes: bytes) -> bytes:
    try:
        return _fernet().decrypt(encrypted_bytes)
    except InvalidToken as exc:
        raise ValueError("The encrypted document could not be decrypted.") from exc


def decrypt_field_file(field_file) -> io.BytesIO:
    field_file.open("rb")
    try:
        encrypted = field_file.read()
    finally:
        field_file.close()
    return io.BytesIO(decrypt_bytes(encrypted))
