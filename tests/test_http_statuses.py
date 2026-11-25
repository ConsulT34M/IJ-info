"""10장 HTTP 응답 표 (진단 증적용).

개별 동작은 각 단계 테스트에 있고, 여기서는 상태 코드 대응만 한곳에서 확인한다.
"""

import time
import uuid
from datetime import timedelta

import pytest
import requests

from app.common.timeutil import now_utc
from app.common.phone import phone_key
from app.models import PhoneOtp, TestPhone, Verification, db

IA01 = "/api/v1/verifications"
BODY = {"client_user_ref": "user-http", "return_url": "http://127.0.0.1:9000/done"}


@pytest.fixture
def person(seeded):
    return seeded[0]


def test_400_bad_format(api_post, flow, carrier_backend, person):
    """형식 오류."""
    assert api_post(IA01, {"return_url": BODY["return_url"]}).status_code == 400
    flow.to_phone()
    assert flow.request_otp("", "01012345678").status_code == 400
    assert flow.post("/verify/consent").status_code == 403  # stage가 먼저 걸린다


def test_401_api_key_signature_timestamp(client, api_post, sign_headers):
    assert client.post(IA01, json=BODY).status_code == 401  # 키 없음
    assert api_post(IA01, BODY, api_key="wrong").status_code == 401  # 키 불일치
    headers = sign_headers(b"{}")
    assert client.post(IA01, data=b'{"x":1}', headers=headers).status_code == 401  # 서명 불일치
    assert api_post(IA01, BODY, timestamp=int(time.time()) - 400).status_code == 401  # 타임스탬프


def test_403_not_allowed_in_this_stage(flow, carrier_backend, person, api_post, exchange_client):
    flow.start()
    assert flow.request_otp(person["name"], person["phone_number"]).status_code == 403
    # 허용 IP가 아닌 위탁사 요청도 403
    exchange_client["client"].allowed_ips = ["10.0.0.1"]
    db.session.commit()
    assert api_post(IA01, BODY).status_code == 403


def test_404_unknown_case(api_get_factory):
    api_get = api_get_factory
    assert api_get(f"{IA01}/{uuid.uuid4()}").status_code == 404
    assert api_get(f"{IA01}/not-a-uuid").status_code == 404


def test_409_finished_case(flow, carrier_backend, sent_webhooks, person, client):
    flow.to_phone()
    verification = db.session.get(Verification, flow.verification_id)
    verification.status = "FAILED"
    verification.reason_code = "P02"
    verification.completed_at = now_utc()
    db.session.commit()
    assert client.get("/verify/phone").status_code == 409


def test_410_entry_token_expired_or_reused(client, api_post):
    body = api_post(IA01, BODY).get_json()
    token = body["auth_url"].rsplit("/", 1)[-1]
    assert client.get(f"/verify/start/{token}").status_code == 302
    assert client.get(f"/verify/start/{token}").status_code == 410  # 재사용
    assert client.get(f"/verify/start/{int(time.time()) - 1}.anything").status_code == 410  # 만료


def test_429_resend_too_soon_and_too_many(flow, carrier_backend, person, app):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    assert flow.resend_otp().status_code == 429  # 60초 이내

    inbox = db.session.get(TestPhone, phone_key(person["phone_number"]))

    def rewind() -> None:
        """발송 제한 창을 과거로 돌린다."""
        db.session.get(PhoneOtp, flow.verification_id).issued_at = now_utc() - timedelta(seconds=61)
        inbox.next_issue_at = now_utc() - timedelta(seconds=1)
        db.session.commit()

    for _ in range(app.config["OTP_MAX_ISSUES"] - 1):
        rewind()
        assert flow.resend_otp().status_code == 200

    rewind()
    assert flow.resend_otp().status_code == 429  # 건당 5회 초과


def test_503_carrier_error(flow, carrier_backend, sent_webhooks, monkeypatch, person):
    """통신사 응답 없음·오류 → P05 종결 + 503."""

    class _ServerError:
        status_code = 500

        def json(self):
            return {}

    flow.to_phone()
    monkeypatch.setattr("app.common.carrier.post_json", lambda *a, **k: _ServerError())
    assert flow.request_otp(person["name"], person["phone_number"]).status_code == 503
    assert db.session.get(Verification, flow.verification_id).reason_code == "P05"


def test_503_when_carrier_matches_without_a_token(flow, carrier_backend, sent_webhooks, monkeypatch, person):
    """MC-01이 일치라면서 대조 토큰을 안 주면 통신사 오류로 본다."""

    class _NoToken:
        status_code = 200

        def json(self):
            return {"matched": True, "reason": None}

    flow.to_phone()
    monkeypatch.setattr("app.common.carrier.post_json", lambda *a, **k: _NoToken())
    assert flow.request_otp(person["name"], person["phone_number"]).status_code == 503
    assert db.session.get(Verification, flow.verification_id).reason_code == "P05"


def test_413_request_too_large(flow, carrier_backend, person, app):
    """MAX_CONTENT_LENGTH를 넘는 요청은 Werkzeug가 끊는다(D54)."""
    flow.to_id_card(person)
    huge = b"\x89PNG\r\n\x1a\n" + b"\x00" * (app.config["MAX_CONTENT_LENGTH"] + 1024)
    response = flow.upload_id_card("id_card.png", huge)
    assert response.status_code == 413
    # 413은 요청을 읽기 전에 끊기므로 시도 횟수에 들어가지 않는다
    assert db.session.get(Verification, flow.verification_id).face_attempts == 0


@pytest.fixture
def api_get_factory(client, sign_headers):
    def _get(path: str, **kwargs):
        return client.get(path, headers=sign_headers(b"", **kwargs))

    return _get
