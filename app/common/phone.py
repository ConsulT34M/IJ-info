"""휴대폰번호 처리와 인증번호 생성·검증.

- 휴대폰번호 원문은 저장하지 않는다. `phone_key = HMAC-SHA256(번호)`와 마스킹값만 쓴다.
- 인증번호 검증은 `code_mac`으로만 한다. 원문은 테스트 수신함용 암호문으로만 남긴다.
- 두 값 모두 verification_id를 함께 묶어 다른 건의 값으로 바꿔치기할 수 없게 한다(D17).
"""

from __future__ import annotations

import re
from secrets import randbelow

from app.common import secrets as secret_store
from app.common.crypto import aad, decrypt_str, encrypt_str, hmac_sha256_hex

CODE_LENGTH = 6
PHONE_PATTERN = re.compile(r"^010\d{8}$")
# 가상 인물 이름만 들어오므로 한글·영문·공백만 받는다
NAME_PATTERN = re.compile(r"^[가-힣a-zA-Z][가-힣a-zA-Z\s]{0,49}$")


def normalize_phone(value: object) -> str | None:
    """하이픈·공백을 떼고 010으로 시작하는 11자리만 받는다."""
    if not isinstance(value, str):
        return None
    digits = re.sub(r"\D", "", value)
    return digits if PHONE_PATTERN.match(digits) else None


def validate_name(value: object) -> str | None:
    """성명 형식 검사. 통과하면 앞뒤 공백을 떼고 돌려준다."""
    if not isinstance(value, str):
        return None
    name = value.strip()
    return name if NAME_PATTERN.match(name) else None


def phone_key(phone_number: str) -> str:
    """번호 식별용 HMAC(A사 자체 키). test_phones·phone_otps 조회에 쓴다."""
    return hmac_sha256_hex(secret_store.get_key("ekyc/phone/phone-hmac-key"), phone_number)


def generate_code() -> str:
    """6자리 인증번호. secrets 모듈로 만든다."""
    return f"{randbelow(10 ** CODE_LENGTH):0{CODE_LENGTH}d}"


def code_mac(verification_id, code: str) -> str:
    """인증번호 검증값. 건에 묶어서 다른 건의 코드가 통하지 않게 한다."""
    return hmac_sha256_hex(
        secret_store.get_key("ekyc/phone/otp-hmac-key"), f"{verification_id}:{code}"
    )


def _inbox_aad(verification_id) -> bytes:
    return aad("phone_otps", "inbox_ciphertext", verification_id)


def encrypt_for_inbox(verification_id, code: str) -> bytes:
    """테스트 수신함 전용 암호문. 사용·만료 즉시 지운다."""
    return encrypt_str(
        secret_store.get_key("ekyc/phone/inbox-key"), code, _inbox_aad(verification_id)
    )


def decrypt_from_inbox(verification_id, blob: bytes) -> str:
    """테스트 수신함에서 인증번호를 꺼낸다(실습 전용)."""
    return decrypt_str(
        secret_store.get_key("ekyc/phone/inbox-key"), blob, _inbox_aad(verification_id)
    )


def encrypt_match_token(verification_id, token: str) -> bytes:
    """대조 토큰은 암호문으로만 보관한다."""
    return encrypt_str(
        secret_store.get_key("ekyc/phone/match-token-key"),
        token,
        aad("phone_verifications", "match_token_enc", verification_id),
    )


def decrypt_match_token(verification_id, blob: bytes) -> str:
    return decrypt_str(
        secret_store.get_key("ekyc/phone/match-token-key"),
        blob,
        aad("phone_verifications", "match_token_enc", verification_id),
    )
