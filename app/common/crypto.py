"""대칭키 암복호화(AES-256-GCM)와 키 기반 요약(HMAC/SHA) 헬퍼.

- 저장용 암호문 형식: nonce(12바이트) + 암호문·태그. 그대로 bytea 컬럼에 넣는다.
- 키는 32바이트. dev_secrets.json에는 Base64 문자열로 보관한다.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from secrets import token_bytes

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12


class DecryptError(Exception):
    """복호화 실패(키 불일치·위조·형식 오류)."""


def generate_key() -> bytes:
    """AES-256용 32바이트 키를 만든다."""
    return token_bytes(KEY_SIZE)


def encode_key(key: bytes) -> str:
    """키를 dev_secrets.json에 넣을 Base64 문자열로 바꾼다."""
    return base64.b64encode(key).decode("ascii")


def decode_key(value: str | bytes) -> bytes:
    """Base64 문자열 또는 bytes를 32바이트 키로 바꾼다."""
    if isinstance(value, bytes):
        key = value
    else:
        try:
            key = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("키 형식이 Base64가 아니다") from exc
    if len(key) != KEY_SIZE:
        raise ValueError(f"키 길이가 {KEY_SIZE}바이트가 아니다: {len(key)}")
    return key


def encrypt(key: str | bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    """AES-256-GCM으로 암호화해 nonce + 암호문을 돌려준다."""
    nonce = token_bytes(NONCE_SIZE)
    sealed = AESGCM(decode_key(key)).encrypt(nonce, plaintext, aad)
    return nonce + sealed


def decrypt(key: str | bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    """encrypt()가 만든 값을 복호화한다. 실패하면 DecryptError."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) <= NONCE_SIZE:
        raise DecryptError("암호문 형식이 아니다")
    blob = bytes(blob)
    try:
        return AESGCM(decode_key(key)).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
    except (InvalidTag, ValueError) as exc:
        raise DecryptError("복호화에 실패했다") from exc


def encrypt_str(key: str | bytes, plaintext: str, aad: bytes | None = None) -> bytes:
    """문자열을 UTF-8로 인코딩해 암호화한다."""
    return encrypt(key, plaintext.encode("utf-8"), aad)


def decrypt_str(key: str | bytes, blob: bytes, aad: bytes | None = None) -> str:
    """암호문을 복호화해 UTF-8 문자열로 돌려준다."""
    return decrypt(key, blob, aad).decode("utf-8")


def aad(table: str, column: str, row_id: object) -> bytes:
    """암호문을 행에 묶는 AAD를 만든다(D17).

    `테이블:컬럼:행 식별자` 형태다. 다른 행의 암호문을 복사해 넣으면 복호화가 실패한다.
    """
    if row_id in (None, ""):
        raise ValueError("AAD에 넣을 행 식별자가 없다")
    return f"{table}:{column}:{row_id}".encode("utf-8")


def _key_bytes(key: str | bytes) -> bytes:
    """HMAC 키를 bytes로 맞춘다. 문자열은 UTF-8 바이트를 쓴다."""
    return key if isinstance(key, bytes) else str(key).encode("utf-8")


def hmac_sha256(key: str | bytes, message: str | bytes) -> bytes:
    """HMAC-SHA256 원본 바이트."""
    msg = message if isinstance(message, bytes) else str(message).encode("utf-8")
    return hmac.new(_key_bytes(key), msg, hashlib.sha256).digest()


def hmac_sha256_hex(key: str | bytes, message: str | bytes) -> str:
    """HMAC-SHA256 소문자 hex(64자). phone_key·rrn_hash·code_mac에 쓴다."""
    return hmac_sha256(key, message).hex()


def hmac_sha512_b64(key: str | bytes, message: str | bytes) -> str:
    """HMAC-SHA512 Base64(88자). ci_mock에 쓴다."""
    msg = message if isinstance(message, bytes) else str(message).encode("utf-8")
    digest = hmac.new(_key_bytes(key), msg, hashlib.sha512).digest()
    return base64.b64encode(digest).decode("ascii")


def sha256_hex(message: str | bytes) -> str:
    """SHA-256 소문자 hex. API Key 해시·토큰 해시에 쓴다."""
    msg = message if isinstance(message, bytes) else str(message).encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


def constant_time_equals(left: str | bytes | None, right: str | bytes | None) -> bool:
    """타이밍 차이를 주지 않는 비교. 둘 중 하나가 없으면 False."""
    if left is None or right is None:
        return False
    a = left if isinstance(left, bytes) else str(left).encode("utf-8")
    b = right if isinstance(right, bytes) else str(right).encode("utf-8")
    return hmac.compare_digest(a, b)
