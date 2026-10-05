"""Криптографические примитивы: PBKDF2-HMAC-SHA256 и AES-256-GCM."""
import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Возвращает (соль base64, хэш hex). Соль случайная, если не задана."""
    salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return base64.b64encode(salt).decode(), digest.hex()


def verify_password(password: str, salt_b64: str, expected_hex: str) -> bool:
    salt = base64.b64decode(salt_b64)
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, expected_hex)


def new_kdf_salt() -> bytes:
    return os.urandom(32)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Ключ шифрования AES-256 из мастер-пароля (ключ на диске не хранится)."""
    return hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, PBKDF2_ITERATIONS)


def encrypt(key: bytes, plaintext: str) -> str:
    """base64(nonce[12] + AESGCM(plaintext)); новый nonce на каждую операцию."""
    nonce = os.urandom(12)
    blob = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + blob).decode()


def decrypt(key: bytes, token: str) -> str:
    raw = base64.b64decode(token)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()
