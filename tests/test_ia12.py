"""IA-12 결과 조회 (웹훅 유실 보완)."""

import uuid

import pytest

from app.common import secrets as secrets_mod
from app.common.ci import ci_mock
from app.common.hmac_auth import api_key_hash, generate_api_key, generate_hmac_secret
from app.models import AccessLog, Client, Verification, db

PATH = "/api/v1/verifications"


@pytest.fixture
def person(seeded):
    return seeded[0]


@pytest.fixture
def api_get(client, sign_headers):
    """본문 없는 GET에 빈 바이트로 서명한다."""

    def _get(path: str, **kwargs):
        return client.get(path, headers=sign_headers(b"", **kwargs))

    return _get


@pytest.fixture
def succeeded(flow, carrier_backend, sent_webhooks, person):
    """성공 완주한 건 하나."""
    flow.to_face(person)
    assert flow.upload_face().status_code == 302
    return flow.verification_id


def test_query_returns_the_same_fields_as_the_webhook(api_get, succeeded, sent_webhooks, person):
    response = api_get(f"{PATH}/{succeeded}")
    assert response.status_code == 200
    body = response.get_json()

    webhook_payload = sent_webhooks[0]["payload"]
    for field in ("product", "verification_id", "status", "reason_code", "stages", "name",
                  "birth_date", "ci_mock", "verified_at"):
        assert body[field] == webhook_payload[field], field

    assert body["ci_mock"] == ci_mock(person["rrn"], secrets_mod.get_key("ekyc/ci-key"))
    assert body["ci_purged_at"] is None  # 아직 보관기한 안
    # 주민번호·이미지는 넣지 않는다
    assert person["rrn"] not in response.get_data(as_text=True)
    assert "rrn" not in body and "s3_key" not in body and "rrn_enc" not in body


def test_query_requires_a_valid_signature(client, api_get, succeeded, exchange_client):
    assert client.get(f"{PATH}/{succeeded}").status_code == 401
    assert client.get(
        f"{PATH}/{succeeded}", headers={"X-Api-Key": exchange_client["api_key"]}
    ).status_code == 401
    assert api_get(f"{PATH}/{succeeded}", api_key="wrong").status_code == 401

    import time

    assert api_get(f"{PATH}/{succeeded}", timestamp=int(time.time()) - 301).status_code == 401


def test_query_is_recorded_in_access_logs(api_get, succeeded, exchange_client):
    api_get(f"{PATH}/{succeeded}")
    log = db.session.scalars(db.select(AccessLog).filter_by(action="RESULT_QUERIED")).one()
    assert log.actor == "client"
    assert log.actor_id == str(exchange_client["client"].id)
    assert log.target_id == str(succeeded)
    assert log.ip == "127.0.0.1"


def test_unknown_id_is_404(api_get, succeeded):
    assert api_get(f"{PATH}/{uuid.uuid4()}").status_code == 404
    assert api_get(f"{PATH}/not-a-uuid").status_code == 404


def test_other_clients_case_is_404_by_default(app, api_get, succeeded):
    """양호 기본값: 다른 위탁사 건은 보이지 않는다(VULN_W08 기본 False)."""
    assert app.config["VULN_W08"] is False
    other = Client(
        name="다른 거래소",
        api_key_hash=api_key_hash(generate_api_key()),
        hmac_secret_ref="ekyc/clients/other/hmac",
        callback_url="http://127.0.0.1:9100/callback",
        allowed_ips=["127.0.0.1"],
    )
    db.session.add(other)
    db.session.flush()  # id는 INSERT 시점에 생긴다
    verification = db.session.get(Verification, succeeded)
    verification.client_id = other.id
    db.session.commit()

    assert api_get(f"{PATH}/{succeeded}").status_code == 404


def test_failed_case_has_no_identity_fields(flow, carrier_backend, sent_webhooks, api_get, person, seeded):
    other_person = seeded[1]
    flow.to_id_card(person)
    flow.upload_id_card()
    flow.submit_id_info(other_person["rrn"], other_person["issue_date"])  # X01

    response = api_get(f"{PATH}/{flow.verification_id}")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "FAILED" and body["reason_code"] == "X01"
    assert body["stages"] == {"phone": "PASSED", "id_card": "FAILED", "face": "NOT_STARTED"}
    assert body["verified_at"] is None
    assert "name" not in body and "birth_date" not in body and "ci_mock" not in body


def test_pending_case_can_be_queried(flow, carrier_backend, api_get, person):
    flow.to_phone()
    response = api_get(f"{PATH}/{flow.verification_id}")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "PENDING" and body["reason_code"] is None
    assert body["stages"]["phone"] == "NOT_STARTED"
    assert body["verified_at"] is None


def test_first_query_records_ci_delivery_when_the_webhook_failed(
    flow, carrier_backend, monkeypatch, api_get, person
):
    """웹훅이 유실되면 첫 IA-12 조회 시점을 CI 전달 시점으로 기록한다."""

    class _Failed:
        status_code = 500

    monkeypatch.setattr("app.api.webhook.post_json", lambda *args, **kwargs: _Failed())

    flow.to_face(person)
    assert flow.upload_face().status_code == 302

    verification = db.session.get(Verification, flow.verification_id)
    assert verification.phone.ci_first_delivered_at is None  # 웹훅 200이 아니었다
    assert [row.http_status for row in verification.callbacks] == [500]

    assert api_get(f"{PATH}/{flow.verification_id}").status_code == 200
    db.session.expire_all()
    verification = db.session.get(Verification, flow.verification_id)
    first_delivered = verification.phone.ci_first_delivered_at
    assert first_delivered is not None
    assert [row.event_kind for row in verification.events][-1] == "CI_DELIVERED"

    # 두 번째 조회로 시점이 바뀌지는 않는다
    api_get(f"{PATH}/{flow.verification_id}")
    db.session.expire_all()
    assert db.session.get(Verification, flow.verification_id).phone.ci_first_delivered_at == first_delivered


def test_query_does_not_resend_the_webhook(flow, carrier_backend, sent_webhooks, api_get, person):
    flow.to_face(person)
    flow.upload_face()
    api_get(f"{PATH}/{flow.verification_id}")
    api_get(f"{PATH}/{flow.verification_id}")
    assert len(sent_webhooks) == 1
