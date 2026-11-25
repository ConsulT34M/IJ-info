"""IA-09 얼굴 대조와 최종 판정, 결과 화면."""

from datetime import date

import pytest

from app.common import secrets as secrets_mod
from app.common.ci import ci_mock
from app.common.storage import get_storage
from app.models import Callback, FaceCheck, IdDocument, Verification, db

RETURN_URL = "http://127.0.0.1:9000/done"


@pytest.fixture
def person(seeded):
    return seeded[0]


def load(verification_id) -> Verification:
    return db.session.get(Verification, verification_id)


def test_success_path_finishes_with_ok(flow, carrier_backend, sent_webhooks, person, client):
    verification_id = flow.to_face(person)
    id_card_key = db.session.get(IdDocument, verification_id).s3_key
    assert get_storage().exists(id_card_key)

    response = flow.upload_face("selfie.png")
    assert response.status_code == 302
    assert response.headers["Location"] == "/verify/result"

    verification = load(verification_id)
    assert verification.status == "SUCCEEDED" and verification.reason_code == "OK"
    assert verification.stage == "DONE" and verification.completed_at is not None
    assert verification.face_attempts == 0 and verification.last_error_code is None

    check = db.session.scalars(db.select(FaceCheck).filter_by(verification_id=verification_id)).one()
    assert check.face_count == 1 and float(check.similarity) == 95.0 and check.matched is True

    # 판정 즉시 이미지 파기
    document = db.session.get(IdDocument, verification_id)
    assert document.s3_key is None and document.deleted_at is not None
    assert check.s3_key is None and check.deleted_at is not None
    assert get_storage().exists(id_card_key) is False

    # 결과 화면
    page = client.get("/verify/result")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "본인확인이 완료됐다" in body and RETURN_URL in body
    assert person["name"] not in body and person["rrn"] not in body


def test_success_webhook_carries_the_identity(flow, carrier_backend, sent_webhooks, person):
    flow.to_face(person)
    flow.upload_face()

    assert len(sent_webhooks) == 1
    payload = sent_webhooks[0]["payload"]
    assert payload["product"] == "ONBOARDING"
    assert payload["status"] == "SUCCEEDED" and payload["reason_code"] == "OK"
    assert payload["stages"] == {"phone": "PASSED", "id_card": "PASSED", "face": "PASSED"}
    assert payload["name"] == person["name"]
    assert payload["birth_date"] == person["birth_date"]
    assert payload["ci_mock"] == ci_mock(person["rrn"], secrets_mod.get_key("ekyc/ci-key"))
    assert len(payload["ci_mock"]) == 88
    assert payload["verified_at"].endswith("+09:00")
    # 주민번호·이미지는 넣지 않는다
    assert person["rrn"] not in sent_webhooks[0]["body"].decode("utf-8")
    assert "rrn" not in payload and "s3_key" not in payload


def test_ci_delivery_is_recorded_on_webhook_200(flow, carrier_backend, sent_webhooks, person):
    verification_id = flow.to_face(person)
    flow.upload_face()
    phone = load(verification_id).phone
    assert phone.ci_first_delivered_at is not None
    kinds = [row.event_kind for row in load(verification_id).events]
    assert kinds[-1] == "CI_DELIVERED"


def test_callback_row_is_recorded(flow, carrier_backend, sent_webhooks, person):
    verification_id = flow.to_face(person)
    flow.upload_face()
    row = db.session.scalars(db.select(Callback).filter_by(verification_id=verification_id)).one()
    assert row.http_status == 200 and row.retry_count == 0
    assert row.url == "http://127.0.0.1:9000/callback"
    assert len(row.payload_hash) == 64


@pytest.mark.parametrize(
    ("filename", "data", "code"),
    [
        ("selfie.gif", None, "E01"),
        ("selfie.png", b"not an image", "E01"),
        ("noface.png", None, "E04"),
        ("twofaces.png", None, "E04"),
        ("selfie_mismatch.png", None, "E05"),
    ],
)
def test_face_failures_are_retryable(flow, carrier_backend, sent_webhooks, person, filename, data, code):
    verification_id = flow.to_face(person)
    response = flow.upload_face(filename, data)
    assert response.status_code == 400

    verification = load(verification_id)
    assert verification.status == "PENDING" and verification.reason_code is None
    assert verification.stage == "FACE"
    assert verification.face_attempts == 1 and verification.last_error_code == code
    assert sent_webhooks == []

    # 신분증 이미지는 아직 남아 있다
    assert db.session.get(IdDocument, verification_id).s3_key is not None


def test_face_check_row_records_each_attempt(flow, carrier_backend, sent_webhooks, person):
    verification_id = flow.to_face(person)
    flow.upload_face("selfie_mismatch.png")
    flow.upload_face("noface.png")

    rows = db.session.scalars(
        db.select(FaceCheck).filter_by(verification_id=verification_id).order_by(FaceCheck.id)
    ).all()
    assert len(rows) == 2
    assert float(rows[0].similarity) == 40.0 and rows[0].matched is False
    assert rows[1].face_count == 0 and rows[1].similarity is None
    # 시도한 셀카는 모두 즉시 파기된다
    assert all(row.s3_key is None and row.deleted_at is not None for row in rows)


def test_third_face_failure_closes_with_e06(flow, carrier_backend, sent_webhooks, person):
    verification_id = flow.to_face(person)
    assert flow.upload_face("selfie_mismatch.png").status_code == 400
    assert flow.upload_face("selfie_mismatch.png").status_code == 400
    third = flow.upload_face("selfie_mismatch.png")
    assert third.status_code == 302 and third.headers["Location"] == RETURN_URL

    verification = load(verification_id)
    assert verification.status == "FAILED" and verification.reason_code == "E06"
    assert verification.last_error_code == "E05"  # 마지막 실패 코드(D8)
    assert verification.face_attempts == 3

    payload = sent_webhooks[0]["payload"]
    assert payload["reason_code"] == "E06"
    assert payload["stages"] == {"phone": "PASSED", "id_card": "PASSED", "face": "FAILED"}
    assert "name" not in payload and "ci_mock" not in payload

    # 종결 시 남은 이미지도 파기한다
    assert db.session.get(IdDocument, verification_id).s3_key is None
    assert db.session.get(IdDocument, verification_id).deleted_at is not None


def test_attempts_are_shared_across_the_id_and_face_steps(flow, carrier_backend, sent_webhooks, person):
    """D10: E01~E05를 한 카운터에 합산한다."""
    verification_id = flow.to_id_card(person)
    assert flow.upload_id_card("noface.png").status_code == 400  # E01
    assert load(verification_id).face_attempts == 1

    flow.upload_id_card("id_card.png")
    flow.submit_id_info(person["rrn"], person["issue_date"])
    assert flow.upload_face("selfie_mismatch.png").status_code == 400  # E05
    assert load(verification_id).face_attempts == 2

    third = flow.upload_face("noface.png")  # E04 → 합산 3회
    assert third.status_code == 302
    assert load(verification_id).reason_code == "E06"
    assert load(verification_id).last_error_code == "E04"


def test_face_step_requires_ci_match(flow, carrier_backend, sent_webhooks, person):
    """D2: 최종 판정은 항상 ci_matched IS TRUE를 요구한다."""
    verification_id = flow.to_face(person)
    document = db.session.get(IdDocument, verification_id)
    document.ci_matched = None
    db.session.commit()

    assert flow.upload_face().status_code == 403
    assert load(verification_id).status == "PENDING"
    assert sent_webhooks == []


def test_face_step_requires_the_mois_check_by_default(flow, carrier_backend, sent_webhooks, person, app):
    """양호 기본값: 진위확인을 통과하지 않으면 얼굴 단계로 갈 수 없다(VULN_W09 기본 False)."""
    assert app.config["VULN_W09"] is False
    verification_id = flow.to_face(person)
    document = db.session.get(IdDocument, verification_id)
    document.mois_matched = False
    db.session.commit()

    assert flow.upload_face().status_code == 403
    assert load(verification_id).status == "PENDING"


def test_result_page_needs_a_result(client):
    assert client.get("/verify/result").status_code == 403


def test_finished_case_cannot_upload_again(flow, carrier_backend, sent_webhooks, person, client):
    verification_id = flow.to_face(person)
    flow.upload_face()
    # 판정 후에는 인증창 세션이 비워지므로 CSRF부터 막히고, 건도 다시 열리지 않는다
    assert flow.upload_face().status_code == 400
    assert client.get("/verify/face").status_code == 403
    assert len(sent_webhooks) == 1
    assert load(verification_id).reason_code == "OK"
