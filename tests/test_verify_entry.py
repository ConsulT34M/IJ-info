"""IA-02 인증창 진입, IA-03 동의, IA-10 취소, @require_stage."""

import re
import time
import uuid
from datetime import timedelta

import pytest

from app.common.crypto import sha256_hex
from app.common.hmac_auth import verify_signature
from app.common.stage import SESSION_ENTRY_NONCE, SESSION_VERIFICATION_ID
from app.common.timeutil import now_utc
from app.models import Consent, Verification, db

IA01 = "/api/v1/verifications"
BODY = {"client_user_ref": "user-0001", "return_url": "http://127.0.0.1:9000/done"}
CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')


def csrf_of(response) -> str:
    return CSRF_PATTERN.search(response.get_data(as_text=True)).group(1)


@pytest.fixture
def entry(api_post):
    """IA-01으로 건을 만들고 토큰·id를 돌려준다."""
    body = api_post(IA01, BODY).get_json()
    return {
        "id": uuid.UUID(body["verification_id"]),
        "token": body["auth_url"].rsplit("/", 1)[-1],
    }


def test_entry_swaps_token_for_server_session(client, entry):
    response = client.get(f"/verify/start/{entry['token']}")
    assert response.status_code == 302
    assert response.headers["Location"] == "/verify/consent"

    row = db.session.get(Verification, entry["id"])
    assert row.token_used_at is not None

    with client.session_transaction() as session:
        assert session[SESSION_VERIFICATION_ID] == str(entry["id"])
        assert session[SESSION_ENTRY_NONCE] == row.entry_nonce
        # 세션에 개인정보는 아직 없다
        assert set(session) <= {SESSION_VERIFICATION_ID, SESSION_ENTRY_NONCE, "_permanent"}


def test_cookie_carries_only_a_session_id(client, entry):
    response = client.get(f"/verify/start/{entry['token']}")
    cookie = response.headers.get("Set-Cookie", "")
    assert "ekyc_session=" in cookie
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert str(entry["id"]) not in cookie


def test_token_is_single_use(client, entry):
    assert client.get(f"/verify/start/{entry['token']}").status_code == 302
    assert client.get(f"/verify/start/{entry['token']}").status_code == 410


def test_unknown_or_tampered_token(client, entry):
    assert client.get("/verify/start/nope").status_code == 410
    assert client.get(f"/verify/start/{int(time.time()) + 600}.forged").status_code == 410
    expires, _, random_part = entry["token"].partition(".")
    assert client.get(f"/verify/start/{int(expires) + 60}.{random_part}").status_code == 410


def test_token_older_than_ten_minutes(client, entry):
    stale = f"{int(time.time()) - 1}.{entry['token'].partition('.')[2]}"
    row = db.session.get(Verification, entry["id"])
    row.token_hash = sha256_hex(stale)
    db.session.commit()
    assert client.get(f"/verify/start/{stale}").status_code == 410
    assert db.session.get(Verification, entry["id"]).token_used_at is None


def test_expired_case_is_closed_with_p03(client, entry, sent_webhooks):
    row = db.session.get(Verification, entry["id"])
    row.created_at = now_utc() - timedelta(minutes=30)
    row.expires_at = now_utc() - timedelta(seconds=1)
    db.session.commit()

    assert client.get(f"/verify/start/{entry['token']}").status_code == 410
    closed = db.session.get(Verification, entry["id"])
    assert closed.status == "EXPIRED" and closed.reason_code == "P03"
    assert closed.stage == "DONE"
    assert len(sent_webhooks) == 1
    assert sent_webhooks[0]["payload"]["status"] == "EXPIRED"


def test_expiry_during_the_flow_closes_the_case(client, entry, sent_webhooks):
    client.get(f"/verify/start/{entry['token']}")
    row = db.session.get(Verification, entry["id"])
    row.created_at = now_utc() - timedelta(minutes=30)
    row.expires_at = now_utc() - timedelta(seconds=1)
    db.session.commit()

    assert client.get("/verify/consent").status_code == 410
    assert db.session.get(Verification, entry["id"]).reason_code == "P03"
    assert len(sent_webhooks) == 1


def test_consent_page_needs_a_session(client):
    assert client.get("/verify/consent").status_code == 403
    # POST는 CSRF 검사가 먼저 걸린다(400). 세션이 없으면 어느 쪽이든 통과하지 못한다
    assert client.post("/verify/consent").status_code == 400


def test_consent_records_four_rows_and_advances_stage(client, entry, app):
    client.get(f"/verify/start/{entry['token']}")
    page = client.get("/verify/consent")
    assert page.status_code == 200

    versions = app.config["CONSENT_VERSIONS"]
    form = {name: "on" for name in versions}
    form.update({f"{name}_version": value for name, value in versions.items()})
    form["csrf_token"] = csrf_of(page)

    response = client.post("/verify/consent", data=form)
    assert response.status_code == 302
    assert response.headers["Location"] == "/verify/phone"

    rows = db.session.scalars(db.select(Consent).filter_by(verification_id=entry["id"])).all()
    assert {row.type for row in rows} == set(versions)
    assert all(row.version == versions[row.type] for row in rows)
    assert all(row.ip == "127.0.0.1" for row in rows)
    assert db.session.get(Verification, entry["id"]).stage == "PHONE"


def test_partial_consent_is_rejected(client, entry, app):
    client.get(f"/verify/start/{entry['token']}")
    page = client.get("/verify/consent")
    versions = app.config["CONSENT_VERSIONS"]
    form = {name: "on" for name in versions if name != "biometric"}
    form.update({f"{name}_version": value for name, value in versions.items()})
    form["csrf_token"] = csrf_of(page)

    response = client.post("/verify/consent", data=form)
    assert response.status_code == 400
    assert db.session.scalar(db.select(db.func.count()).select_from(Consent)) == 0
    assert db.session.get(Verification, entry["id"]).stage == "CONSENT"


def test_stale_terms_version_is_rejected(client, entry, app):
    client.get(f"/verify/start/{entry['token']}")
    page = client.get("/verify/consent")
    versions = app.config["CONSENT_VERSIONS"]
    form = {name: "on" for name in versions}
    form.update({f"{name}_version": "v0.1" for name in versions})
    form["csrf_token"] = csrf_of(page)
    assert client.post("/verify/consent", data=form).status_code == 400
    assert db.session.scalar(db.select(db.func.count()).select_from(Consent)) == 0


def test_consent_without_csrf_token_is_rejected(client, entry, app):
    client.get(f"/verify/start/{entry['token']}")
    client.get("/verify/consent")
    versions = app.config["CONSENT_VERSIONS"]
    form = {name: "on" for name in versions}
    form.update({f"{name}_version": value for name, value in versions.items()})
    assert client.post("/verify/consent", data=form).status_code == 400
    assert db.session.scalar(db.select(db.func.count()).select_from(Consent)) == 0


def test_stage_is_checked_on_the_server(client, entry, app):
    client.get(f"/verify/start/{entry['token']}")
    # CONSENT 단계에서 휴대폰 화면은 403
    assert client.get("/verify/phone").status_code == 403

    page = client.get("/verify/consent")
    versions = app.config["CONSENT_VERSIONS"]
    form = {name: "on" for name in versions}
    form.update({f"{name}_version": value for name, value in versions.items()})
    form["csrf_token"] = csrf_of(page)
    client.post("/verify/consent", data=form)

    # PHONE 단계로 넘어가면 동의 화면은 다시 열리지 않는다
    assert client.get("/verify/phone").status_code == 200
    assert client.get("/verify/consent").status_code == 403
    assert client.post("/verify/consent", data=form).status_code == 403


def test_second_tab_is_invalidated_after_token_reissue(client, entry, api_post):
    """D7: 토큰을 재발급하면 열려 있던 인증창 세션도 무효가 된다."""
    client.get(f"/verify/start/{entry['token']}")
    assert client.get("/verify/consent").status_code == 200

    api_post(IA01, BODY)  # 같은 client_user_ref로 재요청 → 토큰·nonce 재발급
    assert client.get("/verify/consent").status_code == 410
    with client.session_transaction() as session:
        assert SESSION_VERIFICATION_ID not in session


def test_finished_case_cannot_be_reopened(client, entry, sent_webhooks):
    client.get(f"/verify/start/{entry['token']}")
    row = db.session.get(Verification, entry["id"])
    row.status = "FAILED"
    row.reason_code = "P02"
    row.completed_at = now_utc()
    db.session.commit()
    assert client.get("/verify/consent").status_code == 409


def test_cancel_closes_with_p04_and_redirects(client, entry, sent_webhooks, exchange_client):
    client.get(f"/verify/start/{entry['token']}")
    page = client.get("/verify/consent")

    response = client.post("/verify/cancel", data={"csrf_token": csrf_of(page)})
    assert response.status_code == 302
    assert response.headers["Location"] == BODY["return_url"]

    row = db.session.get(Verification, entry["id"])
    assert row.status == "CANCELLED" and row.reason_code == "P04"
    assert row.stage == "DONE" and row.entry_nonce is None

    with client.session_transaction() as session:
        assert SESSION_VERIFICATION_ID not in session

    # 실패 웹훅에는 개인정보가 없다
    assert len(sent_webhooks) == 1
    payload = sent_webhooks[0]["payload"]
    assert payload["product"] == "ONBOARDING"
    assert payload["status"] == "CANCELLED" and payload["reason_code"] == "P04"
    assert payload["verified_at"] is None
    assert payload["stages"] == {
        "phone": "NOT_STARTED",
        "id_card": "NOT_STARTED",
        "face": "NOT_STARTED",
    }
    assert "name" not in payload and "birth_date" not in payload and "ci_mock" not in payload

    # 웹훅도 A사가 같은 방식으로 서명한다
    headers = sent_webhooks[0]["headers"]
    assert verify_signature(
        exchange_client["hmac_secret"],
        headers["X-Timestamp"],
        sent_webhooks[0]["body"],
        headers["X-Signature"],
    )
    assert sent_webhooks[0]["timeout"] == 3


def test_webhook_is_sent_only_once(client, entry, sent_webhooks):
    client.get(f"/verify/start/{entry['token']}")
    page = client.get("/verify/consent")
    client.post("/verify/cancel", data={"csrf_token": csrf_of(page)})
    row = db.session.get(Verification, entry["id"])

    from app.api.webhook import send_result_webhook

    assert send_result_webhook(row) is None
    assert len(sent_webhooks) == 1


def test_no_secrets_appear_in_urls(client, entry):
    """성명·휴대폰번호·인증번호·주민번호·CI는 URL에 넣지 않는다."""
    response = client.get(f"/verify/start/{entry['token']}", follow_redirects=True)
    assert response.status_code == 200
    assert "token" not in response.request.query_string.decode()
    assert response.request.path == "/verify/consent"
