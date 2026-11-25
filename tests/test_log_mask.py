"""마스킹 함수와 로깅 필터."""

import logging

import pytest

from app.common.log_mask import (
    REDACTED,
    MaskingFilter,
    install_masking_filter,
    mask_name,
    mask_phone,
    mask_rrn,
    scrub,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("홍길동", "홍*동"), ("김철", "김*"), ("남궁민수", "남**수"), ("김", "*"), ("", ""), (None, "")],
)
def test_mask_name(raw, expected):
    assert mask_name(raw) == expected


@pytest.mark.parametrize("raw", ["01012341234", "010-1234-1234", "010 1234 1234"])
def test_mask_phone_keeps_only_last_four(raw):
    assert mask_phone(raw) == "010-****-1234"


def test_mask_phone_rejects_short_input():
    assert mask_phone("1234") == REDACTED
    assert mask_phone(None) == ""


def test_mask_rrn_hides_last_six_digits():
    assert mask_rrn("9001011234568") == "900101-1******"
    assert mask_rrn("900101-1234568") == "900101-1******"
    assert mask_rrn("90010112345") == REDACTED
    assert mask_rrn(None) == ""


def test_scrub_removes_rrn_and_ci_and_phone():
    ci = "A" * 86 + "=="
    text = f"rrn=900101-1234568 ci={ci} phone 010-1234-5678"
    out = scrub(text)
    assert "900101-1234568" not in out
    assert ci not in out
    assert "010-1234-5678" not in out
    assert "010-****-5678" in out


def test_scrub_removes_labelled_values():
    out = scrub('{"name": "홍길동", "code": "123456", "match_token": "abc.def"}')
    assert "홍길동" not in out and "123456" not in out and "abc.def" not in out
    assert out.count(REDACTED) == 3


def test_scrub_keeps_korean_labelled_values_out():
    out = scrub("성명: 홍길동, 인증번호 123456, 휴대폰번호 01012341234")
    assert "홍길동" not in out and "123456" not in out and "01012341234" not in out


def test_scrub_keeps_harmless_fields():
    text = 'client_name=SILO verification_id=0e2f-11ef status=SUCCEEDED'
    assert scrub(text) == text


def test_filter_masks_log_output(caplog):
    logger = logging.getLogger("test.masking")
    logger.addFilter(MaskingFilter())
    with caplog.at_level(logging.INFO, logger="test.masking"):
        logger.info("otp sent phone=%s code=%s", "01012341234", "123456")
    assert "01012341234" not in caplog.text
    assert "123456" not in caplog.text
    assert REDACTED in caplog.text


def test_filter_survives_broken_format(caplog):
    logger = logging.getLogger("test.masking.broken")
    install_masking_filter(logger)
    with caplog.at_level(logging.INFO, logger="test.masking.broken"):
        logger.info("missing arg %s %s", "only-one")
    assert caplog.records  # 로깅 자체를 막지 않는다
