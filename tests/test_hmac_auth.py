"""서버 간 API 서명 규칙(거래소와 공유)."""

import pytest

from app.common import hmac_auth
from app.common.hmac_auth import (
    api_key_hash,
    build_signature,
    ip_allowed,
    timestamp_is_fresh,
    verify_signature,
    verify_signed_request,
)

SECRET = "test-secret"
TS = "1700000000"
BODY = b'{"client_user_ref":"u-1"}'
# 거래소 담당에게 넘기는 기준값
KAT_POST = "8d15772196338b56f028ea824940d5cfa11c3716ec0d7cf57675a81d63d071a8"
KAT_GET = "1b74eaf87da46877ba651ac812b24a3bf01990e9ed0101b88268f60f965729e2"


def test_known_answer_post_and_empty_body_get():
    assert build_signature(SECRET, TS, BODY) == KAT_POST
    assert build_signature(SECRET, TS, b"") == KAT_GET
    assert build_signature(SECRET, TS, None) == KAT_GET


def test_signature_is_lowercase_hex_and_case_insensitive_on_compare():
    signature = build_signature(SECRET, TS, BODY)
    assert signature == signature.lower()
    assert verify_signature(SECRET, TS, BODY, signature.upper()) is True
    assert verify_signature(SECRET, TS, BODY, f"  {signature}  ") is True


def test_signature_covers_timestamp_body_and_secret():
    signature = build_signature(SECRET, TS, BODY)
    assert verify_signature(SECRET, "1700000001", BODY, signature) is False
    assert verify_signature(SECRET, TS, BODY + b" ", signature) is False
    assert verify_signature("other-secret", TS, BODY, signature) is False
    assert verify_signature(SECRET, TS, BODY, None) is False
    assert verify_signature(SECRET, TS, BODY, "") is False


def test_timestamp_window_is_five_minutes():
    assert hmac_auth.TIMESTAMP_TOLERANCE_SECONDS == 300
    now = 1700000000
    assert timestamp_is_fresh("1700000300", now=now) is True
    assert timestamp_is_fresh("1699999700", now=now) is True
    assert timestamp_is_fresh("1700000301", now=now) is False
    assert timestamp_is_fresh("1699999699", now=now) is False


@pytest.mark.parametrize("raw", [None, "", "abc", "1700000000.5", "0x1", " "])
def test_non_integer_timestamp_is_rejected(raw):
    assert timestamp_is_fresh(raw, now=1700000000) is False


def test_verify_signed_request_order_timestamp_then_signature():
    signature = build_signature(SECRET, TS, BODY)
    assert verify_signed_request(SECRET, TS, BODY, signature, now=1700000100) is None
    # 타임스탬프가 먼저 걸린다(서명이 맞아도)
    assert verify_signed_request(SECRET, TS, BODY, signature, now=1700001000) == hmac_auth.ERROR_TIMESTAMP
    assert verify_signed_request(SECRET, TS, BODY, "bad", now=1700000100) == hmac_auth.ERROR_SIGNATURE


def test_api_key_is_stored_as_sha256_hash_only():
    key = hmac_auth.generate_api_key()
    digest = api_key_hash(key)
    assert len(digest) == 64 and key not in digest
    assert api_key_hash(key) == digest
    assert api_key_hash(key + "x") != digest


def test_allowed_ip_list():
    assert ip_allowed("127.0.0.1", ["127.0.0.1"]) is True
    assert ip_allowed("10.0.0.7", ["192.168.0.1", "10.0.0.0/24"]) is True
    assert ip_allowed("10.0.1.7", ["10.0.0.0/24"]) is False
    assert ip_allowed("10.0.0.200", ["10.0.0.0/25"]) is False
    assert ip_allowed("10.0.0.7", "10.0.0.0/24, 127.0.0.1") is True


def test_empty_allowlist_denies_by_default():
    # 양호 기본값: 허용 IP가 없으면 통과시키지 않는다
    assert ip_allowed("127.0.0.1", []) is False
    assert ip_allowed("127.0.0.1", None) is False
    assert ip_allowed(None, ["127.0.0.1"]) is False
    assert ip_allowed("not-an-ip", ["127.0.0.1"]) is False
    assert ip_allowed("127.0.0.1", ["not-a-network"]) is False
