"""서버 간 API 서명(위탁사 ↔ A사, A사 → 거래소 웹훅).

거래소와 공유하는 규칙이므로 바꾸면 양쪽을 같이 고쳐야 한다. docs/DECISIONS.md 참고.

    X-Api-Key    위탁사 API Key (A사는 sha256 해시로만 보관)
    X-Timestamp  유닉스 초 문자열 (현재 시각 ±5분)
    X-Signature  hex(HMAC-SHA256(key=HMAC Secret, msg=X-Timestamp 바이트 + 원본 본문 바이트))

구분자 없음, 소문자 hex. 본문 없는 GET은 빈 바이트. HMAC 키는 Secret 문자열의 UTF-8 바이트다.
"""

from __future__ import annotations

import ipaddress
import re
import time
from secrets import token_urlsafe

from app.common.crypto import constant_time_equals, hmac_sha256_hex, sha256_hex

TIMESTAMP_TOLERANCE_SECONDS = 300

# verify_signed_request가 돌려주는 거부 사유 (모두 HTTP 401)
ERROR_API_KEY = "API_KEY"
ERROR_TIMESTAMP = "TIMESTAMP"
ERROR_SIGNATURE = "SIGNATURE"
ERROR_IP = "IP"

_INTEGER = re.compile(r"^-?\d{1,20}$")


def generate_api_key() -> str:
    """위탁사 API Key를 만든다(생성 시 한 번만 출력)."""
    return token_urlsafe(32)


def generate_hmac_secret() -> str:
    """위탁사 HMAC Secret을 만든다. 문자열 그대로 키로 쓴다."""
    return token_urlsafe(32)


def api_key_hash(api_key: str) -> str:
    """API Key는 sha256 해시로만 저장·조회한다."""
    return sha256_hex(api_key)


def build_signature(secret: str | bytes, timestamp: str | int, body: bytes | None) -> str:
    """X-Signature 값을 만든다."""
    payload = str(timestamp).encode("ascii") + (body or b"")
    return hmac_sha256_hex(secret, payload)


def verify_signature(
    secret: str | bytes,
    timestamp: str | int,
    body: bytes | None,
    signature: str | None,
) -> bool:
    """서명을 상수 시간으로 비교한다."""
    if not signature:
        return False
    return constant_time_equals(build_signature(secret, timestamp, body), signature.strip().lower())


def timestamp_is_fresh(
    timestamp: str | int | None,
    now: float | None = None,
    tolerance: int = TIMESTAMP_TOLERANCE_SECONDS,
) -> bool:
    """X-Timestamp가 현재 시각 ±tolerance초 안인지 본다."""
    if timestamp is None or not _INTEGER.match(str(timestamp).strip()):
        return False
    current = time.time() if now is None else now
    return abs(current - int(str(timestamp).strip())) <= tolerance


def verify_signed_request(
    secret: str | bytes,
    timestamp: str | int | None,
    body: bytes | None,
    signature: str | None,
    now: float | None = None,
    tolerance: int = TIMESTAMP_TOLERANCE_SECONDS,
) -> str | None:
    """타임스탬프 → 서명 순으로 본다. 통과하면 None, 아니면 거부 사유."""
    if not timestamp_is_fresh(timestamp, now=now, tolerance=tolerance):
        return ERROR_TIMESTAMP
    if not verify_signature(secret, timestamp, body, signature):
        return ERROR_SIGNATURE
    return None


def ip_allowed(ip: str | None, allowed_ips: list[str] | tuple[str, ...] | str | None) -> bool:
    """허용 IP 목록(단일 IP 또는 CIDR)에 드는지 본다.

    목록이 비어 있으면 거부한다(양호 기본값). 등록 시 허용 IP를 반드시 받는다.
    """
    if not ip or not allowed_ips:
        return False
    entries = allowed_ips.split(",") if isinstance(allowed_ips, str) else list(allowed_ips)
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    for entry in entries:
        candidate = str(entry).strip()
        if not candidate:
            continue
        try:
            if address in ipaddress.ip_network(candidate, strict=False):
                return True
        except ValueError:
            continue
    return False
