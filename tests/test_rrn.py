"""주민번호 체크섬·생년월일, 발급일자 검사."""

from datetime import date

import pytest

from app.common import rrn as rrn_mod
from app.common.rrn import (
    build_rrn,
    checksum_digit,
    normalize_rrn,
    validate_issue_date,
    validate_rrn,
)


def test_checksum_weights_follow_spec():
    # 가중치 2,3,4,5,6,7,8,9,2,3,4,5 → (11 - 합 % 11) % 10
    assert rrn_mod.CHECKSUM_WEIGHTS == (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    first12 = "900101123456"
    total = sum(int(d) * w for d, w in zip(first12, rrn_mod.CHECKSUM_WEIGHTS))
    assert checksum_digit(first12) == (11 - total % 11) % 10


@pytest.mark.parametrize("raw", ["900101-1234568", "9001011234568", " 900101 1234568 "])
def test_normalize_strips_hyphen_and_space(raw):
    assert normalize_rrn(raw) == "9001011234568"


@pytest.mark.parametrize("raw", ["", None, "90010112345", "90010112345678", "90010112345a8"])
def test_normalize_rejects_bad_format(raw):
    assert normalize_rrn(raw) is None
    assert validate_rrn(raw).error == "FORMAT"


def test_valid_rrn_returns_birth_date():
    valid = build_rrn(date(1990, 1, 1), "1", "23456")
    check = validate_rrn(valid)
    assert check.ok is True
    assert check.rrn == valid
    assert check.birth_date == date(1990, 1, 1)


def test_wrong_checksum_is_rejected_and_leaks_nothing():
    valid = build_rrn(date(1990, 1, 1), "1", "23456")
    broken = valid[:12] + str((int(valid[12]) + 1) % 10)
    check = validate_rrn(broken)
    assert check.ok is False
    assert check.error == "CHECKSUM"
    assert check.rrn is None and check.birth_date is None


def test_century_digit_decides_birth_year():
    assert validate_rrn(build_rrn(date(1999, 12, 31), "2", "00001")).birth_date.year == 1999
    assert validate_rrn(build_rrn(date(2005, 6, 15), "3", "00001")).birth_date.year == 2005


@pytest.mark.parametrize("digit", ["0", "5", "6", "7", "8", "9"])
def test_only_gender_digits_1_to_4_are_accepted(digit):
    # D9: 외국인·1800년대 코드는 실습 범위에서 전부 E02로 묶는다
    check = validate_rrn("900101" + digit + "234567")
    assert check.ok is False and check.error == "CENTURY"


def test_impossible_birth_date_is_rejected():
    assert validate_rrn("900230-1234567").error == "BIRTH_DATE"
    assert validate_rrn("901301-1234567").error == "BIRTH_DATE"


def test_build_rrn_guards_arguments():
    with pytest.raises(ValueError):
        build_rrn(date(1990, 1, 1), "3", "23456")  # 세기 불일치
    with pytest.raises(ValueError):
        build_rrn(date(1990, 1, 1), "5", "23456")  # 성별 자리 범위
    with pytest.raises(ValueError):
        build_rrn(date(1990, 1, 1), "1", "234")  # 일련번호 길이


@pytest.mark.parametrize("raw", ["20200101", "2020-1-1", "", None, "2020/01/01"])
def test_issue_date_format_is_fixed(raw):
    assert validate_issue_date(raw).error == "FORMAT"


def test_issue_date_rejects_future_and_before_birth():
    today = date(2026, 11, 26)
    assert validate_issue_date("2026-11-27", today=today).error == "FUTURE"
    assert validate_issue_date("1989-01-01", date(1990, 1, 1), today=today).error == "BEFORE_BIRTH"
    ok = validate_issue_date("2015-03-02", date(1990, 1, 1), today=today)
    assert ok.ok is True and ok.issue_date == date(2015, 3, 2)
