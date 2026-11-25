"""사유 코드별 최종 응답과 웹훅 (진단 증적용 표).

10장의 판정 사유 코드 전부를 한 곳에서 확인한다. 개별 동작은 각 단계 테스트에 있고,
여기서는 "코드 → HTTP 응답 → 웹훅 payload"의 대응만 본다.
"""

from datetime import timedelta

import pytest
import requests

from app.common.timeutil import now_utc
from app.models import IdDocument, Verification, db

RETURN_URL = "http://127.0.0.1:9000/done"
RESULT_PAGE = "/verify/result"


def _expire(verification_id) -> None:
    verification = db.session.get(Verification, verification_id)
    verification.created_at = now_utc() - timedelta(minutes=30)
    verification.expires_at = now_utc() - timedelta(seconds=1)
    db.session.commit()


# --- 시나리오: 각 함수가 마지막 응답을 돌려준다 ---------------------------------


def run_ok(flow, people, monkeypatch):
    flow.to_face(people["person"])
    return flow.upload_face("selfie.png")


def run_p01(flow, people, monkeypatch):
    flow.to_phone()
    person = people["person"]
    for _ in range(2):
        flow.request_otp("다른이름", person["phone_number"])
    return flow.request_otp("다른이름", person["phone_number"])


def run_p02(flow, people, monkeypatch):
    person = people["person"]
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    flow.confirm_otp("000000")
    flow.confirm_otp("000001")
    return flow.confirm_otp("000002")


def run_p03(flow, people, monkeypatch):
    flow.to_phone()
    _expire(flow.verification_id)
    return flow.post("/verify/phone/otp", {"resend": "1"})


def run_p04(flow, people, monkeypatch):
    flow.to_phone()
    return flow.post("/verify/cancel")


def run_p05(flow, people, monkeypatch):
    flow.to_phone()

    def _boom(*args, **kwargs):
        raise requests.ConnectionError("carrier down")

    monkeypatch.setattr("app.common.carrier.post_json", _boom)
    person = people["person"]
    return flow.request_otp(person["name"], person["phone_number"])


def run_x01(flow, people, monkeypatch):
    flow.to_id_card(people["person"])
    flow.upload_id_card()
    other = people["other"]
    return flow.submit_id_info(other["rrn"], other["issue_date"])


def run_e06_id(flow, people, monkeypatch):
    flow.to_id_card(people["person"])
    flow.upload_id_card("noface.png")
    flow.upload_id_card("noface.png")
    return flow.upload_id_card("noface.png")


def run_e06_face(flow, people, monkeypatch):
    flow.to_face(people["person"])
    flow.upload_face("selfie_mismatch.png")
    flow.upload_face("selfie_mismatch.png")
    return flow.upload_face("selfie_mismatch.png")


NOT_STARTED = "NOT_STARTED"
PASSED = "PASSED"
FAILED = "FAILED"

MATRIX = [
    # (이름, 시나리오, 최종 HTTP, Location, status, reason_code, stages)
    ("OK", run_ok, 302, RESULT_PAGE, "SUCCEEDED", "OK", (PASSED, PASSED, PASSED)),
    ("P01", run_p01, 302, RETURN_URL, "FAILED", "P01", (FAILED, NOT_STARTED, NOT_STARTED)),
    ("P02", run_p02, 302, RETURN_URL, "FAILED", "P02", (FAILED, NOT_STARTED, NOT_STARTED)),
    # 휴대폰 단계를 시작하기 전에 끝난 건은 phone도 NOT_STARTED다(phone_verifications 행이 없다)
    ("P03", run_p03, 410, None, "EXPIRED", "P03", (NOT_STARTED, NOT_STARTED, NOT_STARTED)),
    ("P04", run_p04, 302, RETURN_URL, "CANCELLED", "P04", (NOT_STARTED, NOT_STARTED, NOT_STARTED)),
    ("P05", run_p05, 503, None, "FAILED", "P05", (FAILED, NOT_STARTED, NOT_STARTED)),
    ("X01", run_x01, 302, RETURN_URL, "FAILED", "X01", (PASSED, FAILED, NOT_STARTED)),
    ("E06-신분증", run_e06_id, 302, RETURN_URL, "FAILED", "E06", (PASSED, NOT_STARTED, NOT_STARTED)),
    ("E06-얼굴", run_e06_face, 302, RETURN_URL, "FAILED", "E06", (PASSED, PASSED, FAILED)),
]


@pytest.fixture
def people_set(seeded):
    return {
        "person": seeded[0],
        "other": seeded[1],
        "lost": [p for p in seeded if p["person_no"] == 9][0],
    }


@pytest.mark.parametrize(
    ("label", "scenario", "http_status", "location", "status", "reason_code", "stages"),
    MATRIX,
    ids=[row[0] for row in MATRIX],
)
def test_reason_code_matrix(
    flow,
    carrier_backend,
    sent_webhooks,
    people_set,
    monkeypatch,
    label,
    scenario,
    http_status,
    location,
    status,
    reason_code,
    stages,
):
    response = scenario(flow, people_set, monkeypatch)
    assert response.status_code == http_status, label
    if location is not None:
        assert response.headers["Location"] == location, label

    verification = db.session.get(Verification, flow.verification_id)
    assert verification.status == status, label
    assert verification.reason_code == reason_code, label
    assert verification.stage == "DONE", label
    assert verification.completed_at is not None, label
    assert verification.entry_nonce is None, label

    # 웹훅 1회
    assert len(sent_webhooks) == 1, label
    payload = sent_webhooks[0]["payload"]
    assert payload["product"] == "ONBOARDING"
    assert payload["verification_id"] == str(flow.verification_id)
    assert payload["status"] == status and payload["reason_code"] == reason_code
    assert (payload["stages"]["phone"], payload["stages"]["id_card"], payload["stages"]["face"]) == stages

    if status == "SUCCEEDED":
        assert payload["name"] and payload["birth_date"] and payload["ci_mock"]
        assert payload["verified_at"].endswith("+09:00")
    else:
        # 실패·취소·만료 웹훅에는 성명·생년월일·CI를 넣지 않는다
        assert "name" not in payload
        assert "birth_date" not in payload
        assert "ci_mock" not in payload
        assert payload["verified_at"] is None

    # 어떤 경우에도 주민번호·이미지 키는 나가지 않는다
    body = sent_webhooks[0]["body"].decode("utf-8")
    for person in people_set.values():
        assert person["rrn"] not in body
    document = db.session.get(IdDocument, flow.verification_id)
    if document is not None:
        assert document.s3_key is None  # 종결 시 이미지 파기


def test_all_reason_codes_are_covered():
    """10장 코드 전부가 표에 있는지 본다(E01~E05는 중간 코드라 last_error_code로 확인)."""
    from app.models import REASON_CODES

    covered = {row[5] for row in MATRIX}
    intermediate = {"E01", "E02", "E03", "E04", "E05"}
    assert covered | intermediate == set(REASON_CODES)


@pytest.mark.parametrize(
    ("label", "scenario", "expected_code"),
    [
        ("E01", lambda flow, p: flow.upload_id_card("noface.png"), "E01"),
        ("E02", lambda flow, p: flow.submit_after_upload(p, rrn="9001011234567"), "E02"),
        ("E03", lambda flow, p: flow.submit_after_upload(p, lost=True), "E03"),
        ("E04", lambda flow, p: flow.face_after_id(p, "noface.png"), "E04"),
        ("E05", lambda flow, p: flow.face_after_id(p, "selfie_mismatch.png"), "E05"),
    ],
)
def test_intermediate_codes_stay_in_last_error_code(
    flow, carrier_backend, sent_webhooks, people_set, label, scenario, expected_code
):
    """D8: 중간 실패는 last_error_code에만 남고 reason_code는 비어 있다. 웹훅도 보내지 않는다."""
    person = people_set["lost"] if label == "E03" else people_set["person"]

    def submit_after_upload(_flow, _person, rrn=None, lost=False):
        target = people_set["lost"] if lost else _person
        _flow.to_id_card(target)
        _flow.upload_id_card()
        return _flow.submit_id_info(rrn or target["rrn"], target["issue_date"])

    def face_after_id(_flow, _person, filename):
        _flow.to_face(_person)
        return _flow.upload_face(filename)

    flow.submit_after_upload = lambda p, **kwargs: submit_after_upload(flow, p, **kwargs)
    flow.face_after_id = lambda p, filename: face_after_id(flow, p, filename)
    if label == "E01":
        flow.to_id_card(person)

    response = scenario(flow, person)
    assert response.status_code == 400, label

    verification = db.session.get(Verification, flow.verification_id)
    assert verification.status == "PENDING" and verification.reason_code is None
    assert verification.last_error_code == expected_code
    assert verification.face_attempts == 1
    assert sent_webhooks == []
