"""IA-01 인증 요청 (API Key + HMAC 서명)."""

import time
import uuid
from datetime import timedelta

from app.common.crypto import sha256_hex
from app.common.timeutil import now_utc
from app.models import AccessLog, Verification, db

PATH = "/api/v1/verifications"
BODY = {"client_user_ref": "user-0001", "return_url": "http://127.0.0.1:9000/done"}


def token_from(auth_url: str) -> str:
    return auth_url.rsplit("/", 1)[-1]


def load(verification_id: str) -> Verification:
    return db.session.get(Verification, uuid.UUID(verification_id))


def test_new_verification_returns_201_and_auth_url(api_post, app, exchange_client):
    response = api_post(PATH, BODY)
    assert response.status_code == 201, response.get_json()
    body = response.get_json()

    row = load(body["verification_id"])
    assert row is not None
    assert row.client_id == exchange_client["client"].id
    assert row.stage == "CONSENT" and row.status == "PENDING"
    assert row.reason_code is None and row.last_error_code is None
    assert row.return_url == BODY["return_url"]

    # 건 전체 20분
    assert timedelta(minutes=19) < (row.expires_at - row.created_at) <= timedelta(minutes=20)
    assert body["expires_at"].endswith("+09:00")

    # 토큰 평문은 저장하지 않는다
    token = token_from(body["auth_url"])
    assert body["auth_url"].startswith("http://127.0.0.1:8000/verify/start/")
    assert row.token_hash == sha256_hex(token)
    assert row.token_used_at is None
    assert row.entry_nonce  # D7

    # 토큰 유효기간 10분이 토큰 안에 담긴다(D36)
    expires_part = int(token.split(".")[0])
    assert 9 * 60 < expires_part - int(time.time()) <= 10 * 60


def test_request_is_recorded_in_access_logs(api_post, exchange_client):
    body = api_post(PATH, BODY).get_json()
    log = db.session.scalars(db.select(AccessLog).filter_by(action="REQUEST_RECEIVED")).one()
    assert log.actor == "client"
    assert log.actor_id == str(exchange_client["client"].id)
    assert log.target_id == body["verification_id"]
    assert log.ip == "127.0.0.1"


def test_same_user_ref_returns_existing_case_with_200(api_post):
    first = api_post(PATH, BODY).get_json()
    response = api_post(PATH, BODY)
    assert response.status_code == 200
    second = response.get_json()

    # D12: 같은 건, 토큰만 새로 발급
    assert second["verification_id"] == first["verification_id"]
    assert second["expires_at"] == first["expires_at"]
    assert token_from(second["auth_url"]) != token_from(first["auth_url"])

    row = load(first["verification_id"])
    assert row.token_hash == sha256_hex(token_from(second["auth_url"]))


def test_old_token_stops_working_after_reissue(api_post, client):
    first = api_post(PATH, BODY).get_json()
    api_post(PATH, BODY)
    assert client.get(f"/verify/start/{token_from(first['auth_url'])}").status_code == 410


def test_different_user_ref_creates_another_case(api_post):
    first = api_post(PATH, BODY).get_json()
    second = api_post(PATH, {**BODY, "client_user_ref": "user-0002"})
    assert second.status_code == 201
    assert second.get_json()["verification_id"] != first["verification_id"]


def test_expired_pending_case_is_closed_and_replaced(api_post, sent_webhooks):
    first = api_post(PATH, BODY).get_json()
    row = load(first["verification_id"])
    row.created_at = now_utc() - timedelta(minutes=30)
    row.expires_at = now_utc() - timedelta(minutes=10)
    db.session.commit()

    response = api_post(PATH, BODY)
    assert response.status_code == 201
    assert response.get_json()["verification_id"] != first["verification_id"]

    closed = load(first["verification_id"])
    assert closed.status == "EXPIRED" and closed.reason_code == "P03"
    assert [call["payload"]["reason_code"] for call in sent_webhooks] == ["P03"]


def test_finished_case_does_not_block_a_new_request(api_post, sent_webhooks):
    first = api_post(PATH, BODY).get_json()
    row = load(first["verification_id"])
    row.status = "CANCELLED"
    row.reason_code = "P04"
    row.completed_at = now_utc()
    db.session.commit()

    response = api_post(PATH, BODY)
    assert response.status_code == 201


def test_missing_api_key(client):
    assert client.post(PATH, json=BODY).status_code == 401


def test_unknown_api_key(api_post):
    assert api_post(PATH, BODY, api_key="wrong-key").status_code == 401


def test_suspended_client_is_rejected(api_post, exchange_client):
    exchange_client["client"].status = "SUSPENDED"
    db.session.commit()
    assert api_post(PATH, BODY).status_code == 401


def test_bad_signature(client, sign_headers):
    headers = sign_headers(b'{"a":1}')
    assert client.post(PATH, data=b'{"client_user_ref":"x"}', headers=headers).status_code == 401


def test_stale_or_future_timestamp(api_post):
    assert api_post(PATH, BODY, timestamp=int(time.time()) - 301).status_code == 401
    assert api_post(PATH, BODY, timestamp=int(time.time()) + 301).status_code == 401
    assert api_post(PATH, BODY, timestamp=int(time.time()) - 299).status_code == 201


def test_missing_timestamp_or_signature(client, exchange_client):
    assert client.post(
        PATH, json=BODY, headers={"X-Api-Key": exchange_client["api_key"]}
    ).status_code == 401


def test_ip_not_in_allowlist_is_rejected(api_post, exchange_client):
    exchange_client["client"].allowed_ips = ["10.0.0.1"]
    db.session.commit()
    response = api_post(PATH, BODY)
    assert response.status_code == 403
    assert db.session.scalar(db.select(db.func.count()).select_from(Verification)) == 0


def test_api_is_csrf_exempt(app, api_post):
    # 서명으로 보호하므로 CSRF 토큰 없이도 통과한다
    assert app.config["WTF_CSRF_ENABLED"] is True
    assert api_post(PATH, BODY).status_code == 201


def test_missing_or_bad_client_user_ref(api_post):
    assert api_post(PATH, {"return_url": BODY["return_url"]}).status_code == 400
    assert api_post(PATH, {**BODY, "client_user_ref": "  "}).status_code == 400
    assert api_post(PATH, {**BODY, "client_user_ref": "x" * 101}).status_code == 400
    assert api_post(PATH, {**BODY, "client_user_ref": 12345}).status_code == 400


def test_return_url_must_be_absolute_and_same_origin(api_post):
    """D5: 오픈 리다이렉트 방지."""
    for bad in [
        "/done",
        "javascript:alert(1)",
        "http://evil.example/done",
        "http://127.0.0.1:9999/done",
        "https://127.0.0.1:9000/done",
        None,
        "",
    ]:
        response = api_post(PATH, {**BODY, "return_url": bad})
        assert response.status_code == 400, bad
    assert db.session.scalar(db.select(db.func.count()).select_from(Verification)) == 0


def test_non_json_body_is_rejected(client, sign_headers):
    body = b"client_user_ref=user-1"
    assert client.post(PATH, data=body, headers=sign_headers(body)).status_code == 400
