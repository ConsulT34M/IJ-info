"""로그·화면용 마스킹과 로깅 필터.

성명·휴대폰번호·인증번호·주민번호 원문, CI, 대조 토큰, 인증창 토큰은 로그에 남기지 않는다.
코드에서 애초에 넣지 않는 것이 1차 방어고, 이 필터는 2차 방어다.
VULN_W17을 켜면 이 필터를 거치지 않는 로거로 인증번호·번호를 남긴다(9단계).
"""

from __future__ import annotations

import logging
import re

REDACTED = "[REDACTED]"

# 값 자체를 알아볼 수 있는 패턴
_RRN_PATTERN = re.compile(r"(?<![0-9])\d{6}[\s-]?[1-4]\d{6}(?![0-9])")
_PHONE_PATTERN = re.compile(r"(?<![0-9])(01[016789])[\s-]?(\d{3,4})[\s-]?(\d{4})(?![0-9])")
_CI_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{86}==(?![A-Za-z0-9+/=])")

# key=value / "key": "value" 형태
_SENSITIVE_KEYS = (
    "name",
    "phone",
    "phone_number",
    "code",
    "otp",
    "otp_code",
    "rrn",
    "resident_number",
    "ci",
    "ci_mock",
    "token",
    "match_token",
    "entry_token",
    "inbox_key",
    "password",
    "api_key",
    "hmac_secret",
    "secret",
)
_KEY_ALTERNATION = "|".join(sorted(_SENSITIVE_KEYS, key=len, reverse=True))
_JSON_KV_PATTERN = re.compile(
    r'("(?:' + _KEY_ALTERNATION + r')"\s*:\s*)"[^"]*"',
    re.IGNORECASE,
)
_PLAIN_KV_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])((?:" + _KEY_ALTERNATION + r")\s*[=:]\s*)([^\s,;&)}\]\"']+)",
    re.IGNORECASE,
)
_KOREAN_LABEL_PATTERN = re.compile(
    r"(성명|이름|휴대폰번호|휴대폰|인증번호|주민번호|주민등록번호)\s*[:=]?\s*"
    r"([가-힣]{2,5}|[\d-]{4,14})"
)


def mask_name(name: str | None) -> str:
    """성명 마스킹. 홍길동 → 홍*동, 김철 → 김*."""
    if not name:
        return ""
    text = str(name).strip()
    if len(text) <= 1:
        return "*"
    if len(text) == 2:
        return text[0] + "*"
    return text[0] + "*" * (len(text) - 2) + text[-1]


def mask_phone(phone: str | None) -> str:
    """휴대폰번호 마스킹. 01012341234 → 010-****-1234."""
    if not phone:
        return ""
    digits = re.sub(r"\D", "", str(phone))
    if len(digits) < 9:
        return REDACTED
    return f"{digits[:3]}-****-{digits[-4:]}"


def mask_rrn(rrn: str | None) -> str:
    """주민번호 마스킹. 뒤 6자리를 가린다. 9001011234568 → 900101-1******."""
    if not rrn:
        return ""
    digits = re.sub(r"\D", "", str(rrn))
    if len(digits) != 13:
        return REDACTED
    return f"{digits[:6]}-{digits[6]}******"


def scrub(text: str) -> str:
    """로그 한 줄에서 민감한 값을 지운다."""
    if not text:
        return text
    out = _RRN_PATTERN.sub("[RRN]", text)
    out = _PHONE_PATTERN.sub(lambda m: f"{m.group(1)}-****-{m.group(3)}", out)
    out = _CI_PATTERN.sub("[CI]", out)
    out = _JSON_KV_PATTERN.sub(lambda m: f'{m.group(1)}"{REDACTED}"', out)
    out = _PLAIN_KV_PATTERN.sub(lambda m: f"{m.group(1)}{REDACTED}", out)
    out = _KOREAN_LABEL_PATTERN.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    return out


class MaskingFilter(logging.Filter):
    """로그 레코드를 포매팅한 뒤 민감한 값을 지우는 필터."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            # 포매팅이 깨진 레코드는 핸들러에서 다시 터지지 않게 여기서 평평하게 만든다
            record.msg = scrub(f"[로그 포맷 오류] msg={record.msg!r} args={record.args!r}")
            record.args = ()
            return True
        masked = scrub(message)
        if masked != message:
            record.msg = masked
            record.args = ()
        if record.exc_text:
            record.exc_text = scrub(record.exc_text)
        return True


def install_masking_filter(logger: logging.Logger) -> MaskingFilter:
    """로거(와 그 핸들러)에 마스킹 필터를 건다."""
    masking = MaskingFilter()
    logger.addFilter(masking)
    for handler in logger.handlers:
        handler.addFilter(masking)
    return masking
