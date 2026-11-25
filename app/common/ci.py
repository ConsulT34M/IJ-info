"""연계정보(CI) 모사값 계산.

ci_mock = Base64(HMAC-SHA512(key=CI 공유키, msg=하이픈 없는 주민번호 13자리)) → 88자.
A사(`ekyc/ci-key`)와 모의 통신사(`carrier/ci-key`)가 같은 키를 쓰므로,
같은 인물이면 휴대폰 본인확인으로 받은 CI와 신분증 주민번호로 계산한 CI가 같아진다(X-01 대조).
"""

from __future__ import annotations

from app.common.crypto import constant_time_equals, hmac_sha512_b64
from app.common.rrn import normalize_rrn

CI_LENGTH = 88


def ci_mock(rrn: str, key: str | bytes) -> str:
    """주민번호로 CI 모사값(88자)을 만든다."""
    digits = normalize_rrn(rrn)
    if digits is None:
        raise ValueError("주민번호 13자리가 필요하다")
    value = hmac_sha512_b64(key, digits)
    assert len(value) == CI_LENGTH
    return value


def ci_matches(left: str | None, right: str | None) -> bool:
    """CI 두 값을 상수 시간으로 비교한다(X-01)."""
    return constant_time_equals(left, right)
