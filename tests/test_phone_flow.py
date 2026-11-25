"""IA-04 명의 대조·인증번호 발송, IA-05 테스트 수신함, IA-06 인증번호 확인 → CI 수령."""

from datetime import timedelta

import pytest
import requests

from app.common import secrets as secrets_mod
from app.common.ci import ci_mock
from app.common.phone import code_mac, phone_key
from app.common.stage import SESSION_NAME, SESSION_PHONE_NUMBER
from app.common.timeutil import now_utc
from app.models import PhoneEvent, PhoneOtp, PhoneVerification, TestPhone, Verification, db

RETURN_URL = "http://127.0.0.1:9000/done"


@pytest.fixture
def person(seeded):
    return seeded[0]


@pytest.fixture
def other_person(seeded):
    return seeded[1]


def events(verification_id) -> list[tuple[str, str | None]]:
    rows = db.session.scalars(
        db.select(PhoneEvent).filter_by(verification_id=verification_id).order_by(PhoneEvent.id)
    ).all()
    return [(row.event_kind, row.result_code) for row in rows]


def test_successful_phone_verification_receives_ci(flow, carrier_backend, person, client):
    verification_id = flow.to_phone()

    response = flow.request_otp(person["name"], person["phone_number"])
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert person["phone_number"][-4:] in page  # 마스킹된 번호만 보인다
    assert person["phone_number"] not in page

    code = flow.inbox_code(person["inbox_key"])
    assert code is not None and len(code) == 6
    assert code not in page  # 인증창 화면에는 인증번호가 없다

    confirmed = flow.confirm_otp(code)
    assert confirmed.status_code == 302
    assert confirmed.headers["Location"] == "/verify/id-card"

    verification = db.session.get(Verification, verification_id)
    assert verification.stage == "ID_CARD" and verification.status == "PENDING"

    phone = db.session.get(PhoneVerification, verification_id)
    assert phone.status == "PASSED"
    assert phone.completed_at is not None
    assert phone.match_token_enc is None  # CI 발급 후 폐기
    assert phone.ci_first_delivered_at is None and phone.ci_purged_at is None
    assert len(phone.ci) == 88
    assert phone.ci == ci_mock(person["rrn"], secrets_mod.get_key("ekyc/ci-key"))

    otp = db.session.get(PhoneOtp, verification_id)
    assert otp.code_mac is None and otp.inbox_ciphertext is None  # 사용 즉시 삭제
    assert otp.phone_key == phone_key(person["phone_number"])

    assert events(verification_id) == [
        ("IDENTITY_MATCH", None),
        ("OTP_ISSUED", None),
        ("OTP_VERIFIED", None),
        ("CI_ISSUED", None),
    ]
    masked = db.session.scalars(
        db.select(PhoneEvent).filter_by(verification_id=verification_id, event_kind="IDENTITY_MATCH")
    ).one()
    assert masked.name_mask and masked.phone_mask == f"010-****-{person['phone_number'][-4:]}"

    # 성명은 서버 세션에만 둔다
    with client.session_transaction() as session:
        assert session[SESSION_NAME] == person["name"]
        assert session[SESSION_PHONE_NUMBER] == person["phone_number"]
    assert person["name"] not in str(client.get_cookie("ekyc_session").value)


def test_different_person_gets_a_different_ci(flow, carrier_backend, person, other_person):
    """X-01 대조가 성립하려면 사람마다 CI가 달라야 한다."""
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    flow.confirm_otp(flow.inbox_code(person["inbox_key"]))
    received = db.session.get(PhoneVerification, flow.verification_id).ci

    ci_key = secrets_mod.get_key("ekyc/ci-key")
    assert received == ci_mock(person["rrn"], ci_key)
    assert received != ci_mock(other_person["rrn"], ci_key)


def test_carrier_call_uses_pinned_certificate(flow, carrier_backend, person, app):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    call = carrier_backend[0]
    assert call["url"].startswith(app.config["CARRIER_BASE_URL"])
    assert call["verify"] == app.config["CARRIER_CA_BUNDLE"]  # 시스템 신뢰 저장소가 아니다
    assert call["headers"]["X-Carrier-Client-Key"]
    assert call["timeout"] == app.config["CARRIER_TIMEOUT"]
    assert call["payload"]["phone_number"] == person["phone_number"]


def test_name_mismatch_and_unknown_number_look_the_same(flow, carrier_backend, person, app):
    """D1 양호: 사유를 구분하지 않고 P01 한 가지 메시지·같은 상태 코드."""
    flow.to_phone()
    wrong_name = flow.request_otp("다른이름", person["phone_number"])
    unknown_number = flow.request_otp(person["name"], "01099998888")

    assert wrong_name.status_code == unknown_number.status_code == 200
    first = wrong_name.get_data(as_text=True)
    second = unknown_number.get_data(as_text=True)
    assert "성명 또는 휴대폰번호가 일치하지 않는다" in first
    assert "등록되지 않은" not in first and "등록되지 않은" not in second
    assert "명의자와 다르다" not in first

    verification = db.session.get(Verification, flow.verification_id)
    assert verification.last_error_code == "P01"  # D8
    assert verification.status == "PENDING" and verification.reason_code is None
    phone = db.session.get(PhoneVerification, flow.verification_id)
    assert phone.match_attempts == 2
    assert events(flow.verification_id) == [
        ("IDENTITY_MATCH", "P01"),
        ("IDENTITY_MATCH", "P01"),
    ]
    assert db.session.get(PhoneOtp, flow.verification_id) is None


def test_third_match_failure_closes_the_case(flow, carrier_backend, person, sent_webhooks):
    flow.to_phone()
    flow.request_otp("다른이름", person["phone_number"])
    flow.request_otp("다른이름", person["phone_number"])
    third = flow.request_otp("다른이름", person["phone_number"])

    assert third.status_code == 302
    assert third.headers["Location"] == RETURN_URL

    verification = db.session.get(Verification, flow.verification_id)
    assert verification.status == "FAILED" and verification.reason_code == "P01"
    assert verification.stage == "DONE"
    phone = db.session.get(PhoneVerification, flow.verification_id)
    assert phone.match_attempts == 3 and phone.status == "FAILED"

    assert len(sent_webhooks) == 1
    payload = sent_webhooks[0]["payload"]
    assert payload["reason_code"] == "P01" and payload["status"] == "FAILED"
    assert payload["stages"]["phone"] == "FAILED"
    assert "name" not in payload and "ci_mock" not in payload


def test_bad_input_does_not_reach_the_carrier(flow, carrier_backend, person):
    flow.to_phone()
    for name, number in [
        ("", person["phone_number"]),
        ("<script>", person["phone_number"]),
        (person["name"], "011-1234-5678"),
        (person["name"], "0101234"),
        (person["name"], ""),
    ]:
        response = flow.post("/verify/phone/otp", {"name": name, "phone_number": number})
        assert response.status_code == 400, (name, number)
    assert carrier_backend == []
    assert db.session.get(PhoneVerification, flow.verification_id).match_attempts == 0


def test_carrier_outage_closes_with_p05(flow, app, monkeypatch, person, sent_webhooks):
    flow.to_phone()

    def _boom(*args, **kwargs):
        raise requests.ConnectionError("carrier down")

    monkeypatch.setattr("app.common.carrier.requests.post", _boom)
    response = flow.request_otp(person["name"], person["phone_number"])
    assert response.status_code == 503

    verification = db.session.get(Verification, flow.verification_id)
    assert verification.status == "FAILED" and verification.reason_code == "P05"
    assert len(sent_webhooks) == 1 and sent_webhooks[0]["payload"]["reason_code"] == "P05"


def test_resend_is_rate_limited_then_allowed(flow, carrier_backend, person, app):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    calls_after_match = len(carrier_backend)

    blocked = flow.resend_otp()
    assert blocked.status_code == 429
    assert "60초" in blocked.get_data(as_text=True)

    # 60초가 지난 상황으로 만든다
    _rewind_issue_window(flow.verification_id, person, seconds=61)
    allowed = flow.resend_otp()
    assert allowed.status_code == 200

    otp = db.session.get(PhoneOtp, flow.verification_id)
    assert otp.issue_no == 2
    # D6: 재발송은 명의 대조를 다시 하지 않는다
    assert len(carrier_backend) == calls_after_match
    assert events(flow.verification_id)[-1] == ("OTP_REISSUED", None)


def test_issue_count_is_capped_per_case(flow, carrier_backend, person, app):
    """D11: 건당 5회까지. 넘으면 429이고 건은 종결하지 않는다."""
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])

    for _ in range(app.config["OTP_MAX_ISSUES"] - 1):
        _rewind_issue_window(flow.verification_id, person, seconds=61)
        assert flow.resend_otp().status_code == 200

    assert db.session.get(PhoneOtp, flow.verification_id).issue_no == app.config["OTP_MAX_ISSUES"]

    _rewind_issue_window(flow.verification_id, person, seconds=61)
    response = flow.resend_otp()
    assert response.status_code == 429
    assert "5회" in response.get_data(as_text=True)

    verification = db.session.get(Verification, flow.verification_id)
    assert verification.status == "PENDING" and verification.reason_code is None


def test_number_level_limit_blocks_a_second_case(flow, carrier_backend, person):
    """D11: 새 건을 만들어도 같은 번호면 60초 제한이 걸린다."""
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    inbox = db.session.get(TestPhone, phone_key(person["phone_number"]))
    assert inbox.next_issue_at is not None and inbox.next_issue_at > now_utc()

    first_case = flow.verification_id
    flow.to_phone(client_user_ref="user-0002")
    assert flow.verification_id != first_case

    blocked = flow.request_otp(person["name"], person["phone_number"])
    assert blocked.status_code == 429
    assert db.session.get(PhoneOtp, flow.verification_id) is None
    # 명의 대조는 성공했으므로 그 기록은 남는다
    assert events(flow.verification_id) == [("IDENTITY_MATCH", None)]


def test_wrong_code_three_times_closes_with_p02(flow, carrier_backend, person, sent_webhooks):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])

    assert flow.confirm_otp("000000").status_code in (400, 302)
    assert flow.confirm_otp("000001").status_code == 400
    third = flow.confirm_otp("000002")
    assert third.status_code == 302 and third.headers["Location"] == RETURN_URL

    verification = db.session.get(Verification, flow.verification_id)
    assert verification.status == "FAILED" and verification.reason_code == "P02"
    phone = db.session.get(PhoneVerification, flow.verification_id)
    assert phone.otp_attempts == 3
    assert len(sent_webhooks) == 1 and sent_webhooks[0]["payload"]["reason_code"] == "P02"


def test_malformed_code_does_not_consume_attempts(flow, carrier_backend, person):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    for bad in ["", "abc", "12345", "1234567", " 123 "]:
        assert flow.confirm_otp(bad).status_code == 400
    assert db.session.get(PhoneVerification, flow.verification_id).otp_attempts == 0


def test_expired_code_is_not_a_mismatch(flow, carrier_backend, person):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    code = flow.inbox_code(person["inbox_key"])

    otp = db.session.get(PhoneOtp, flow.verification_id)
    otp.code_expires_at = now_utc() - timedelta(seconds=1)
    db.session.commit()

    response = flow.confirm_otp(code)
    assert response.status_code == 400
    assert "만료" in response.get_data(as_text=True)
    assert db.session.get(PhoneVerification, flow.verification_id).otp_attempts == 0


def test_code_cannot_be_reused_after_success(flow, carrier_backend, person):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    code = flow.inbox_code(person["inbox_key"])
    assert flow.confirm_otp(code).status_code == 302
    # stage가 ID_CARD로 넘어갔으므로 휴대폰 단계 요청은 403
    assert flow.confirm_otp(code).status_code == 403
    assert flow.request_otp(person["name"], person["phone_number"]).status_code == 403


def test_code_is_bound_to_the_case(flow, carrier_backend, person):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    code = flow.inbox_code(person["inbox_key"])
    otp = db.session.get(PhoneOtp, flow.verification_id)
    # 같은 코드라도 다른 건의 MAC과는 다르다
    assert otp.code_mac == code_mac(flow.verification_id, code)
    assert otp.code_mac != code_mac("00000000-0000-0000-0000-000000000000", code)


def test_phone_step_requires_the_phone_stage(flow, carrier_backend, person):
    flow.start()
    # 동의 전에는 403
    assert flow.post("/verify/phone/otp", {"name": person["name"], "phone_number": person["phone_number"]}).status_code == 403
    assert flow.post("/verify/phone/confirm", {"code": "123456"}).status_code == 403


def test_confirm_without_an_issued_code(flow, carrier_backend, person):
    flow.to_phone()
    response = flow.confirm_otp("123456")
    assert response.status_code == 400
    assert "인증번호를 먼저 받는다" in response.get_data(as_text=True)


def test_logs_do_not_contain_the_code_or_the_number(flow, carrier_backend, person, caplog):
    import logging

    with caplog.at_level(logging.DEBUG):
        flow.to_phone()
        flow.request_otp(person["name"], person["phone_number"])
        code = flow.inbox_code(person["inbox_key"])
        flow.confirm_otp(code)

    text = caplog.text
    assert person["phone_number"] not in text
    assert person["rrn"] not in text
    assert code not in text


def _rewind_issue_window(verification_id, person, *, seconds: int) -> None:
    """발송 제한 창을 과거로 돌린다."""
    otp = db.session.get(PhoneOtp, verification_id)
    otp.issued_at = now_utc() - timedelta(seconds=seconds)
    inbox = db.session.get(TestPhone, phone_key(person["phone_number"]))
    inbox.next_issue_at = now_utc() - timedelta(seconds=1)
    db.session.commit()
