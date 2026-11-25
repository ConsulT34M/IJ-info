"""주민등록번호 체크섬·생년월일 검사와 발급일자 검사.

여기서 나오는 error 값은 내부용이다. 호출부는 전부 E02로 묶어 이용자에게 보여준다.
가상 주민번호만 다룬다(체크섬만 맞춘 실습용 값).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

RRN_LENGTH = 13
CHECKSUM_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)

# 7번째 자리 → 출생 세기. 1·2는 1900년대, 3·4는 2000년대만 허용한다(D9).
CENTURY_BY_GENDER_DIGIT = {"1": 1900, "2": 1900, "3": 2000, "4": 2000}

_DIGITS_ONLY = re.compile(r"^\d{13}$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class RrnCheck:
    """주민번호 검사 결과."""

    ok: bool
    rrn: str | None = None
    birth_date: date | None = None
    error: str | None = None  # FORMAT / CENTURY / BIRTH_DATE / CHECKSUM


@dataclass(frozen=True)
class IssueDateCheck:
    """발급일자 검사 결과."""

    ok: bool
    issue_date: date | None = None
    error: str | None = None  # FORMAT / FUTURE / BEFORE_BIRTH


def normalize_rrn(value: str | None) -> str | None:
    """하이픈·공백을 떼고 13자리 숫자만 남긴다. 형식이 아니면 None."""
    if not value:
        return None
    digits = re.sub(r"[\s-]", "", str(value))
    return digits if _DIGITS_ONLY.match(digits) else None


def checksum_digit(first12: str) -> int:
    """앞 12자리로 13번째 자리를 계산한다."""
    if len(first12) != 12 or not first12.isdigit():
        raise ValueError("앞 12자리 숫자가 필요하다")
    total = sum(int(d) * w for d, w in zip(first12, CHECKSUM_WEIGHTS))
    return (11 - total % 11) % 10


def birth_date_from_rrn(rrn13: str) -> date | None:
    """주민번호에서 생년월일을 뽑는다. 세기 코드나 날짜가 틀리면 None."""
    century = CENTURY_BY_GENDER_DIGIT.get(rrn13[6])
    if century is None:
        return None
    try:
        return date(century + int(rrn13[0:2]), int(rrn13[2:4]), int(rrn13[4:6]))
    except ValueError:
        return None


def validate_rrn(value: str | None) -> RrnCheck:
    """형식 → 세기 코드 → 생년월일 → 체크섬 순서로 검사한다."""
    rrn = normalize_rrn(value)
    if rrn is None:
        return RrnCheck(ok=False, error="FORMAT")
    if rrn[6] not in CENTURY_BY_GENDER_DIGIT:
        return RrnCheck(ok=False, error="CENTURY")
    birth = birth_date_from_rrn(rrn)
    if birth is None:
        return RrnCheck(ok=False, error="BIRTH_DATE")
    if int(rrn[12]) != checksum_digit(rrn[0:12]):
        return RrnCheck(ok=False, rrn=None, birth_date=None, error="CHECKSUM")
    return RrnCheck(ok=True, rrn=rrn, birth_date=birth)


def validate_issue_date(
    value: str | None,
    birth_date: date | None = None,
    today: date | None = None,
) -> IssueDateCheck:
    """발급일자는 YYYY-MM-DD 고정. 미래 날짜·생년월일 이전은 거부한다."""
    if not value or not _ISO_DATE.match(str(value)):
        return IssueDateCheck(ok=False, error="FORMAT")
    try:
        issued = date.fromisoformat(str(value))
    except ValueError:
        return IssueDateCheck(ok=False, error="FORMAT")
    if issued > (today or date.today()):
        return IssueDateCheck(ok=False, error="FUTURE")
    if birth_date is not None and issued < birth_date:
        return IssueDateCheck(ok=False, error="BEFORE_BIRTH")
    return IssueDateCheck(ok=True, issue_date=issued)


def build_rrn(birth_date: date, gender_digit: str, serial: str) -> str:
    """가상 인물 시드용. 체크섬이 맞는 13자리를 만든다.

    serial은 성별 자리 다음의 5자리(지역·순번)다.
    """
    if gender_digit not in CENTURY_BY_GENDER_DIGIT:
        raise ValueError("성별 자리는 1~4만 쓴다")
    if len(serial) != 5 or not serial.isdigit():
        raise ValueError("일련번호 5자리가 필요하다")
    expected_century = CENTURY_BY_GENDER_DIGIT[gender_digit]
    if expected_century != (birth_date.year // 100) * 100:
        raise ValueError("성별 자리와 출생 세기가 맞지 않는다")
    first12 = f"{birth_date:%y%m%d}{gender_digit}{serial}"
    return first12 + str(checksum_digit(first12))
