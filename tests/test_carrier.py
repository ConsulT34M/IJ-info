"""모의 통신사 MC-01 / MC-02."""

import uuid
from datetime import timedelta

import pytest

from app.common import secrets as secrets_mod
from app.common.ci import ci_mock
from app.common.crypto import sha256_hex
from app.common.timeutil import now_utc
from carrier.models import CarrierClient, MatchSession, Subscriber, db as carrier_db
from carrier.routes import REASON_NAME_MISMATCH, REASON_NOT_SUBSCRIBER

MATCH_PATH = "/carrier/v1/identity-matches"
CI_PATH = "/carrier/v1/ci-issuances"
UNKNOWN_PHONE = "01099998888"


@pytest.fixture
def carrier_http(carrier_app):
    return carrier_app.test_client()


@pytest.fixture
def client_key(dev_secrets):
    return {"X-Carrier-Client-Key": secrets_mod.get_secret("ekyc/phone/carrier-client-key")}


@pytest.fixture
def person(people):
    return people[0]


def test_client_key_is_required(carrier_http, person):
    body = {"verification_id": "v-1", "name": person["name"], "phone_number": person["phone_number"]}
    assert carrier_http.post(MATCH_PATH, json=body).status_code == 401
    assert carrier_http.post(
        MATCH_PATH, json=body, headers={"X-Carrier-Client-Key": "wrong"}
    ).status_code == 401


def test_suspended_client_is_rejected(carrier_http, client_key, carrier_app, person):
    with carrier_app.app_context():
        row = carrier_db.session.scalars(carrier_db.select(CarrierClient)).one()
        row.status = "SUSPENDED"
        carrier_db.session.commit()
    body = {"verification_id": "v-1", "name": person["name"], "phone_number": person["phone_number"]}
    assert carrier_http.post(MATCH_PATH, json=body, headers=client_key).status_code == 401


def test_match_succeeds_and_returns_a_token(carrier_http, client_key, person, carrier_app):
    response = carrier_http.post(
        MATCH_PATH,
        json={
            "verification_id": "11111111-1111-1111-1111-111111111111",
            "name": person["name"],
            "phone_number": person["phone_number"],
        },
        headers=client_key,
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["matched"] is True and body["reason"] is None
    assert body["match_token"] and body["expires_at"].endswith("+09:00")

    with carrier_app.app_context():
        row = carrier_db.session.get(MatchSession, sha256_hex(body["match_token"]))
        assert row is not None and row.used_at is None
        assert row.verification_id == "11111111-1111-1111-1111-111111111111"
        # 토큰 평문은 저장하지 않는다
        assert body["match_token"] not in row.token_digest
        assert timedelta(minutes=4) < (row.expires_at - now_utc()) <= timedelta(minutes=5)


def test_hyphenated_number_matches(carrier_http, client_key, person):
    digits = person["phone_number"]
    hyphenated = f"{digits[:3]}-{digits[3:7]}-{digits[7:]}"
    response = carrier_http.post(
        MATCH_PATH,
        json={"verification_id": "v-1", "name": person["name"], "phone_number": hyphenated},
        headers=client_key,
    )
    assert response.get_json()["matched"] is True


def test_unknown_number_and_name_mismatch_have_internal_reasons(carrier_http, client_key, person):
    """D1: 통신사는 사유를 구분해 주고, A사가 기본(양호)에서 P01로 합친다."""
    not_subscriber = carrier_http.post(
        MATCH_PATH,
        json={"verification_id": "v-1", "name": person["name"], "phone_number": UNKNOWN_PHONE},
        headers=client_key,
    )
    assert not_subscriber.status_code == 200
    assert not_subscriber.get_json() == {"matched": False, "reason": REASON_NOT_SUBSCRIBER}

    name_mismatch = carrier_http.post(
        MATCH_PATH,
        json={"verification_id": "v-1", "name": "다른이름", "phone_number": person["phone_number"]},
        headers=client_key,
    )
    assert name_mismatch.status_code == 200
    assert name_mismatch.get_json() == {"matched": False, "reason": REASON_NAME_MISMATCH}


def test_match_rejects_bad_input(carrier_http, client_key, person):
    for body in [
        {"name": person["name"], "phone_number": person["phone_number"]},
        {"verification_id": "v-1", "phone_number": person["phone_number"]},
        {"verification_id": "v-1", "name": person["name"]},
        {"verification_id": "v-1", "name": person["name"], "phone_number": "011-1234-5678"},
        {"verification_id": "v-1", "name": "", "phone_number": person["phone_number"]},
    ]:
        assert carrier_http.post(MATCH_PATH, json=body, headers=client_key).status_code == 400
    assert carrier_http.post(MATCH_PATH, data=b"not-json", headers=client_key).status_code == 400


def _match(carrier_http, client_key, person, verification_id="v-ci"):
    response = carrier_http.post(
        MATCH_PATH,
        json={
            "verification_id": verification_id,
            "name": person["name"],
            "phone_number": person["phone_number"],
        },
        headers=client_key,
    )
    return response.get_json()["match_token"]


def test_ci_issuance_matches_the_shared_formula(carrier_http, client_key, person, dev_secrets):
    token = _match(carrier_http, client_key, person)
    response = carrier_http.post(
        CI_PATH, json={"verification_id": "v-ci", "match_token": token}, headers=client_key
    )
    assert response.status_code == 200
    ci = response.get_json()["ci"]
    assert len(ci) == 88
    # A사가 주민번호로 직접 계산한 값과 같아야 X-01이 통과한다
    assert ci == ci_mock(person["rrn"], secrets_mod.get_key("ekyc/ci-key"))


def test_match_token_is_single_use(carrier_http, client_key, person, carrier_app):
    token = _match(carrier_http, client_key, person)
    body = {"verification_id": "v-ci", "match_token": token}
    assert carrier_http.post(CI_PATH, json=body, headers=client_key).status_code == 200
    assert carrier_http.post(CI_PATH, json=body, headers=client_key).status_code == 409
    with carrier_app.app_context():
        assert carrier_db.session.get(MatchSession, sha256_hex(token)).used_at is not None


def test_match_token_is_bound_to_the_verification(carrier_http, client_key, person):
    token = _match(carrier_http, client_key, person, verification_id="v-one")
    response = carrier_http.post(
        CI_PATH, json={"verification_id": "v-two", "match_token": token}, headers=client_key
    )
    assert response.status_code == 409


def test_expired_or_unknown_match_token(carrier_http, client_key, person, carrier_app):
    assert carrier_http.post(
        CI_PATH, json={"verification_id": "v-ci", "match_token": "nope"}, headers=client_key
    ).status_code == 409

    token = _match(carrier_http, client_key, person)
    with carrier_app.app_context():
        row = carrier_db.session.get(MatchSession, sha256_hex(token))
        row.expires_at = now_utc() - timedelta(seconds=1)
        carrier_db.session.commit()
    assert carrier_http.post(
        CI_PATH, json={"verification_id": "v-ci", "match_token": token}, headers=client_key
    ).status_code == 409


def test_ci_issuance_rejects_bad_input(carrier_http, client_key):
    for body in [{}, {"verification_id": "v-1"}, {"match_token": "x"}]:
        assert carrier_http.post(CI_PATH, json=body, headers=client_key).status_code == 400


def test_subscriber_rows_hold_no_plaintext(carrier_app, people):
    with carrier_app.app_context():
        rows = carrier_db.session.scalars(carrier_db.select(Subscriber)).all()
        assert len(rows) == 10
        dumped = " ".join(
            f"{row.subscriber_ref}{row.phone_key}{row.name_mac}{row.name_mask}" for row in rows
        )
        blob = b"".join(row.rrn_ciphertext for row in rows)
        for person in people:
            assert person["phone_number"] not in dumped
            assert person["name"] not in dumped
            assert person["rrn"] not in dumped
            assert person["rrn"].encode() not in blob


def test_carrier_client_key_is_stored_as_hash_only(carrier_app, dev_secrets):
    with carrier_app.app_context():
        row = carrier_db.session.scalars(carrier_db.select(CarrierClient)).one()
        key = secrets_mod.get_secret("ekyc/phone/carrier-client-key")
        assert row.key_digest == sha256_hex(key) and key not in row.key_digest
