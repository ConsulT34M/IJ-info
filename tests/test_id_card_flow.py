"""IA-07 신분증 업로드, IA-08 체크섬 → X-01 → 진위확인."""

from datetime import date, timedelta

import pytest

from app import mock_mois
from app.common import secrets as secrets_mod
from app.common.crypto import aad, decrypt_str
from app.common.storage import get_storage
from app.common.timeutil import now_utc
from app.models import AccessLog, IdDocument, PhoneVerification, Verification, db
from tests.conftest import sample_jpg, sample_png

RETURN_URL = "http://127.0.0.1:9000/done"


@pytest.fixture
def person(seeded):
    """진위확인 대장에 정상으로 등록된 인물."""
    return seeded[0]


@pytest.fixture
def lost_person(seeded):
    """9번 인물. 대장에서 분실 상태라 E03이 난다."""
    return [p for p in seeded if p["person_no"] == 9][0]


@pytest.fixture
def other_person(seeded):
    return seeded[1]


def load(verification_id) -> Verification:
    return db.session.get(Verification, verification_id)


def test_upload_creates_the_row_and_stores_the_image(flow, carrier_backend, person, app):
    """D41: IA-07 시점에 id_documents 행이 생긴다(주민번호는 아직 없다)."""
    verification_id = flow.to_id_card(person)
    response = flow.upload_id_card("id_card.png")
    assert response.status_code == 302
    assert response.headers["Location"] == "/verify/id-confirm"

    document = db.session.get(IdDocument, verification_id)
    assert document is not None
    assert document.name == person["name"]  # 서버 세션의 성명
    assert document.rrn_enc is None and document.birth_date is None and document.issue_date is None
    assert document.ci_matched is None and document.mois_matched is None
    assert document.deleted_at is None

    # 웹 루트 밖, UUID 파일명으로 저장된다(W-04)
    assert document.s3_key and document.s3_key.endswith(".png")
    assert "id_card" not in document.s3_key
    assert get_storage().exists(document.s3_key)
    assert str(app.config["UPLOAD_DIR"]) not in str(app.static_folder)

    assert load(verification_id).stage == "ID_CONFIRM"
    assert load(verification_id).face_attempts == 0


def test_full_id_step_passes_for_the_same_person(flow, carrier_backend, person):
    verification_id = flow.to_id_card(person)
    flow.upload_id_card()
    response = flow.submit_id_info(person["rrn"], person["issue_date"])
    assert response.status_code == 302
    assert response.headers["Location"] == "/verify/face"

    document = db.session.get(IdDocument, verification_id)
    assert document.ci_matched is True and document.mois_matched is True
    assert document.birth_date == date.fromisoformat(person["birth_date"])
    assert document.issue_date == date.fromisoformat(person["issue_date"])

    # 주민번호는 암호문으로만 보관되고 건에 묶인다
    assert person["rrn"].encode() not in document.rrn_enc
    assert decrypt_str(
        secrets_mod.get_key("ekyc/rrn-key"),
        document.rrn_enc,
        aad("id_documents", "rrn_enc", verification_id),
    ) == person["rrn"]

    verification = load(verification_id)
    assert verification.stage == "FACE" and verification.status == "PENDING"
    assert verification.face_attempts == 0 and verification.last_error_code is None


def test_name_in_the_request_body_is_ignored(flow, carrier_backend, person):
    """W-16: 성명은 서버 세션 값으로 고정한다."""
    verification_id = flow.to_id_card(person)
    flow.upload_id_card()
    response = flow.submit_id_info(person["rrn"], person["issue_date"], name="다른사람")
    assert response.status_code == 302
    document = db.session.get(IdDocument, verification_id)
    assert document.name == person["name"] and document.mois_matched is True


def test_hyphenated_rrn_is_accepted(flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    digits = person["rrn"]
    assert flow.submit_id_info(f"{digits[:6]}-{digits[6:]}", person["issue_date"]).status_code == 302


def test_rrn_back_digits_are_masked_on_screen(flow, carrier_backend, person, client):
    """F-05: 뒤 7자리는 화면에 보이지 않는 입력칸으로 받는다(D79)."""
    flow.to_id_card(person)
    flow.upload_id_card()
    body = client.get("/verify/id-confirm").get_data(as_text=True)
    assert 'name="rrn_front"' in body and 'maxlength="6"' in body
    assert 'type="password"' in body and 'name="rrn_back"' in body
    assert "뒤 7자리는 화면에 표시되지 않는다" in body


def test_single_rrn_field_still_works(flow, carrier_backend, person):
    """스크립트·점검 도구가 한 칸으로 보내도 받아준다(D79)."""
    flow.to_id_card(person)
    flow.upload_id_card()
    response = flow.post(
        "/verify/id-confirm",
        {"rrn": person["rrn"], "issue_date": person["issue_date"]},
    )
    assert response.status_code == 302
    assert db.session.get(IdDocument, flow.verification_id).mois_matched is True


def test_rrn_halves_are_joined_even_with_a_hyphen(flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    digits = person["rrn"]
    response = flow.post(
        "/verify/id-confirm",
        {
            "rrn_front": f"{digits[:6]}-",
            "rrn_back": digits[6:],
            "issue_date": person["issue_date"],
        },
    )
    assert response.status_code == 302


def test_id_step_requires_ci(flow, carrier_backend, person):
    """W-12: 신분증 단계 요청마다 CI 수령 완료를 확인한다."""
    verification_id = flow.to_id_card(person)
    phone = db.session.get(PhoneVerification, verification_id)
    phone.ci = None
    db.session.commit()

    assert flow.upload_id_card().status_code == 403
    assert flow.post("/verify/id-card").status_code == 403


@pytest.mark.parametrize(
    ("filename", "data"),
    [
        ("id_card.gif", None),
        ("id_card", None),
        ("id_card.png", b"not an image"),
        ("id_card.png", b""),
        ("noface.png", None),
        ("twofaces.png", None),
    ],
)
def test_bad_image_is_e01(flow, carrier_backend, person, filename, data):
    verification_id = flow.to_id_card(person)
    response = flow.upload_id_card(filename, data)
    assert response.status_code == 400

    verification = load(verification_id)
    assert verification.face_attempts == 1
    assert verification.last_error_code == "E01"
    assert verification.stage == "ID_CARD" and verification.status == "PENDING"
    # 거부된 이미지는 행도 파일도 남기지 않는다
    assert db.session.get(IdDocument, verification_id) is None


def test_oversized_image_is_e01(flow, carrier_backend, person, app):
    verification_id = flow.to_id_card(person)
    oversized = sample_png() + b"\x00" * (app.config["UPLOAD_MAX_BYTES"] + 1)
    assert flow.upload_id_card("id_card.png", oversized).status_code == 400
    assert load(verification_id).last_error_code == "E01"


def test_third_image_failure_closes_with_e06(flow, carrier_backend, person, sent_webhooks):
    verification_id = flow.to_id_card(person)
    assert flow.upload_id_card("noface.png").status_code == 400
    assert flow.upload_id_card("noface.png").status_code == 400
    third = flow.upload_id_card("noface.png")
    assert third.status_code == 302 and third.headers["Location"] == RETURN_URL

    verification = load(verification_id)
    assert verification.status == "FAILED" and verification.reason_code == "E06"
    assert verification.face_attempts == 3
    assert verification.last_error_code == "E01"  # 마지막 실패 코드는 이력에 남는다(D8)

    assert len(sent_webhooks) == 1
    payload = sent_webhooks[0]["payload"]
    assert payload["reason_code"] == "E06"
    assert payload["stages"] == {"phone": "PASSED", "id_card": "NOT_STARTED", "face": "NOT_STARTED"}
    assert "name" not in payload and "ci_mock" not in payload


def test_reupload_replaces_and_deletes_the_previous_file(flow, carrier_backend, person):
    """D41: 재업로드 때 이전 파일은 즉시 Storage에서 지운다."""
    verification_id = flow.to_id_card(person)
    flow.upload_id_card("id_card.png")
    first_key = db.session.get(IdDocument, verification_id).s3_key
    assert get_storage().exists(first_key)

    # 같은 건을 다시 ID_CARD 단계로 돌려 재업로드 경로를 지나가게 한다
    verification = load(verification_id)
    verification.stage = "ID_CARD"
    db.session.commit()

    assert flow.upload_id_card("id_card.jpg", sample_jpg()).status_code == 302
    document = db.session.get(IdDocument, verification_id)
    assert document.s3_key != first_key and document.s3_key.endswith(".jpg")
    assert get_storage().exists(document.s3_key)
    assert get_storage().exists(first_key) is False


@pytest.mark.parametrize(
    "rrn",
    ["9001011234567", "90010112345", "abcdefghijklm", "900101-5234567", "900230-1234567", ""],
)
def test_bad_rrn_is_e02(flow, carrier_backend, person, rrn):
    verification_id = flow.to_id_card(person)
    flow.upload_id_card()
    response = flow.submit_id_info(rrn, person["issue_date"])
    assert response.status_code == 400

    verification = load(verification_id)
    assert verification.face_attempts == 1 and verification.last_error_code == "E02"
    assert verification.stage == "ID_CONFIRM"
    document = db.session.get(IdDocument, verification_id)
    assert document.rrn_enc is None and document.ci_matched is None


@pytest.mark.parametrize("issue_date", ["20200101", "2020-1-1", "", "2099-01-01", "1900-01-01"])
def test_bad_issue_date_is_e02(flow, carrier_backend, person, issue_date):
    """D9: 발급일자 형식·미래·생년월일 이전도 E02로 묶고 시도에 포함한다."""
    verification_id = flow.to_id_card(person)
    flow.upload_id_card()
    assert flow.submit_id_info(person["rrn"], issue_date).status_code == 400
    assert load(verification_id).last_error_code == "E02"
    assert load(verification_id).face_attempts == 1


def test_ci_mismatch_closes_immediately_with_x01(
    flow, carrier_backend, person, other_person, sent_webhooks
):
    """X-01: 휴대폰 명의자와 신분증 명의자가 다르면 재시도 없이 종결한다(W-13)."""
    verification_id = flow.to_id_card(person)
    flow.upload_id_card()
    response = flow.submit_id_info(other_person["rrn"], other_person["issue_date"])
    assert response.status_code == 302 and response.headers["Location"] == RETURN_URL

    verification = load(verification_id)
    assert verification.status == "FAILED" and verification.reason_code == "X01"
    assert verification.stage == "DONE"
    assert verification.face_attempts == 0  # 재시도가 없으므로 시도 횟수와 무관하다

    document = db.session.get(IdDocument, verification_id)
    assert document.ci_matched is False
    assert document.mois_matched is None  # 진위확인까지 가지 않는다
    assert document.rrn_enc is not None  # 증적으로 입력값은 남긴다(암호문)

    log = db.session.scalars(db.select(AccessLog).filter_by(action="CI_MISMATCH")).one()
    assert log.actor == "system" and log.target_id == str(verification_id)
    assert log.ip == "127.0.0.1"

    payload = sent_webhooks[0]["payload"]
    assert payload["reason_code"] == "X01" and payload["status"] == "FAILED"
    assert payload["stages"] == {"phone": "PASSED", "id_card": "FAILED", "face": "NOT_STARTED"}
    assert payload["verified_at"] is None
    assert "name" not in payload and "birth_date" not in payload and "ci_mock" not in payload


def test_lost_id_is_e03_and_can_be_retried(flow, carrier_backend, lost_person, sent_webhooks):
    """9번 인물은 대장에서 분실 상태라 진위확인에서 걸린다."""
    verification_id = flow.to_id_card(lost_person)
    flow.upload_id_card()
    response = flow.submit_id_info(lost_person["rrn"], lost_person["issue_date"])
    assert response.status_code == 400

    verification = load(verification_id)
    assert verification.status == "PENDING" and verification.reason_code is None
    assert verification.last_error_code == "E03" and verification.face_attempts == 1
    assert verification.stage == "ID_CONFIRM"

    document = db.session.get(IdDocument, verification_id)
    assert document.ci_matched is True and document.mois_matched is False
    assert sent_webhooks == []


def test_third_e03_closes_with_e06(flow, carrier_backend, lost_person, sent_webhooks):
    verification_id = flow.to_id_card(lost_person)
    flow.upload_id_card()
    flow.submit_id_info(lost_person["rrn"], lost_person["issue_date"])
    flow.submit_id_info(lost_person["rrn"], lost_person["issue_date"])
    third = flow.submit_id_info(lost_person["rrn"], lost_person["issue_date"])
    assert third.status_code == 302

    verification = load(verification_id)
    assert verification.reason_code == "E06" and verification.last_error_code == "E03"
    assert sent_webhooks[0]["payload"]["stages"]["id_card"] == "FAILED"


def test_wrong_issue_date_is_e03_not_x01(flow, carrier_backend, person):
    """같은 사람이라 CI는 맞고 발급일자만 대장과 다르면 E03이다."""
    verification_id = flow.to_id_card(person)
    flow.upload_id_card()
    other_date = (date.fromisoformat(person["issue_date"]) - timedelta(days=1)).isoformat()
    assert flow.submit_id_info(person["rrn"], other_date).status_code == 400
    assert load(verification_id).last_error_code == "E03"
    assert db.session.get(IdDocument, verification_id).ci_matched is True


def test_stage_order_is_enforced(flow, carrier_backend, person, client):
    flow.to_id_card(person)
    # 업로드 전에는 정보 입력도, 다음 화면도 열리지 않는다
    assert flow.submit_id_info(person["rrn"], person["issue_date"]).status_code == 403
    assert client.get("/verify/id-confirm").status_code == 403
    assert client.get("/verify/face").status_code == 403
    assert client.get("/verify/id-card").status_code == 200

    flow.upload_id_card()
    assert client.get("/verify/id-confirm").status_code == 200
    assert client.get("/verify/id-card").status_code == 403
    assert flow.upload_id_card().status_code == 403  # 업로드는 한 번만

    assert flow.submit_id_info(person["rrn"], person["issue_date"]).status_code == 302
    assert client.get("/verify/face").status_code == 200
    assert flow.submit_id_info(person["rrn"], person["issue_date"]).status_code == 403


def test_mock_mois_has_no_http_route(client, app):
    """D3: 모의 진위확인은 함수 호출이고 공개 라우트가 없다."""
    paths = [str(rule) for rule in app.url_map.iter_rules()]
    assert not [path for path in paths if "mois" in path or "authenticity" in path]
    for path in ["/mock-mois", "/api/v1/mois", "/mois/verify"]:
        assert client.get(path).status_code == 404


def test_mock_mois_verify_function(seeded, person, lost_person):
    issue_date = date.fromisoformat(person["issue_date"])
    assert mock_mois.verify(person["name"], person["rrn"], issue_date) is True
    assert mock_mois.verify(person["name"], f"{person['rrn'][:6]}-{person['rrn'][6:]}", issue_date) is True

    # 이름·발급일자 불일치
    assert mock_mois.verify("다른사람", person["rrn"], issue_date) is False
    assert mock_mois.verify(person["name"], person["rrn"], issue_date - timedelta(days=1)) is False
    # 미등록 주민번호
    assert mock_mois.verify(person["name"], "9001011234568", issue_date) is False
    # 분실 상태
    assert mock_mois.verify(
        lost_person["name"], lost_person["rrn"], date.fromisoformat(lost_person["issue_date"])
    ) is False
    # 형식 오류
    assert mock_mois.verify(person["name"], "abc", issue_date) is False
    assert mock_mois.verify("", person["rrn"], issue_date) is False
    assert mock_mois.verify(person["name"], person["rrn"], "2015-03-02") is False


def test_registry_keeps_no_plaintext_rrn(seeded):
    from app.models import MockMoisRegistry

    rows = db.session.scalars(db.select(MockMoisRegistry)).all()
    dumped = " ".join(f"{row.name}{row.rrn_hash}{row.issue_date}" for row in rows)
    for person in seeded:
        assert person["rrn"] not in dumped


def test_expiry_during_the_id_step(flow, carrier_backend, person, sent_webhooks):
    verification_id = flow.to_id_card(person)
    verification = load(verification_id)
    verification.created_at = now_utc() - timedelta(minutes=30)
    verification.expires_at = now_utc() - timedelta(seconds=1)
    db.session.commit()

    assert flow.upload_id_card().status_code == 410
    assert load(verification_id).reason_code == "P03"
    assert sent_webhooks[0]["payload"]["stages"]["phone"] == "PASSED"
