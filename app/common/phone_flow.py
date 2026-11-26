"""휴대폰 본인확인 단계의 공용 로직.

인증창(IA-04·IA-06)과 위탁사 서버 경로(IA-23·IA-24)가 **같은 함수**를 쓴다.
D2에서 decision.py를 둔 것과 같은 이유다 — 한쪽만 고쳐서 두 경로의 통제가
달라지는 일을 막는다(D98).

여기 있는 함수는 HTTP를 모른다. 화면·응답 만들기는 호출하는 쪽이 한다.
"""

from __future__ import annotations

from secrets import token_urlsafe

from flask import current_app

from app.common import carrier
from app.common.audit import log_phone_event
from app.common.crypto import sha256_hex
from app.common.log_mask import mask_phone, unmasked_logger
from app.common.phone import (
    code_mac,
    encrypt_for_inbox,
    generate_code,
    phone_key,
)
from app.common.timeutil import is_expired, now_utc
from app.models import PhoneOtp, PhoneVerification, TestPhone, Verification, db


def ensure_phone_row(verification: Verification) -> PhoneVerification:
    """휴대폰 단계 행을 만들거나 가져온다."""
    row = db.session.get(PhoneVerification, verification.id)
    if row is None:
        row = PhoneVerification(verification_id=verification.id)
        db.session.add(row)
        db.session.flush()
    return row


def ensure_test_phone(number: str) -> TestPhone:
    """번호 단위 발송 제한(D11)에 쓸 행. 명부에 없는 번호면 읽을 수 없는 수신함으로 만든다."""
    key = phone_key(number)
    row = db.session.get(TestPhone, key)
    if row is None:
        current_app.logger.warning(
            "테스트 수신함에 없는 번호다. 발송 제한만 적용한다: %s", mask_phone(number)
        )
        row = TestPhone(
            phone_key=key,
            phone_mask=mask_phone(number),
            inbox_key_hash=sha256_hex(token_urlsafe(32)),
        )
        db.session.add(row)
        db.session.flush()
    return row


def issue_block_reason(otp_row: PhoneOtp | None, test_phone: TestPhone) -> str | None:
    """발송을 막아야 하는 이유(D11). 없으면 None."""
    if otp_row is not None:
        if otp_row.issue_no >= current_app.config["OTP_MAX_ISSUES"]:
            return "MAX_ISSUES"
        if not is_expired(otp_row.issued_at + current_app.config["OTP_RESEND_INTERVAL"]):
            return "INTERVAL"
    if test_phone.next_issue_at and not is_expired(test_phone.next_issue_at):
        return "INTERVAL"
    return None


def issue_code(
    verification: Verification,
    otp_row: PhoneOtp | None,
    number: str,
    test_phone: TestPhone,
) -> PhoneOtp:
    """인증번호를 만들어 검증값·수신함 암호문을 저장한다.

    **인증번호를 만드는 주체는 A사다.** 모의 통신사는 명의 대조(MC-01)와 CI 발급(MC-02)만
    한다. 원문은 어디에도 남기지 않는다 — 검증은 code_mac(HMAC), 수신함 열람은
    inbox_ciphertext(AES-GCM)로만 한다.
    """
    code = generate_code()
    issued_at = now_utc()
    expires_at = issued_at + current_app.config["OTP_TTL"]

    if otp_row is None:
        otp_row = PhoneOtp(
            verification_id=verification.id,
            phone_key=phone_key(number),
            issue_no=1,
            issued_at=issued_at,
            code_expires_at=expires_at,
        )
        db.session.add(otp_row)
        event_kind = "OTP_ISSUED"
    else:
        otp_row.issue_no += 1
        otp_row.phone_key = phone_key(number)
        otp_row.issued_at = issued_at
        otp_row.code_expires_at = expires_at
        event_kind = "OTP_REISSUED"

    otp_row.code_mac = code_mac(verification.id, code)
    otp_row.inbox_ciphertext = encrypt_for_inbox(verification.id, code)
    test_phone.next_issue_at = issued_at + current_app.config["OTP_RESEND_INTERVAL"]
    log_phone_event(verification.id, event_kind)

    if current_app.config.get("VULN_W17"):
        # VULN_W17: 마스킹 필터를 거치지 않는 로거로 인증번호·번호 원문을 남긴다(실습 전용)
        unmasked_logger().debug(
            "otp issued verification_id=%s phone_number=%s code=%s",
            verification.id,
            number,
            code,
        )

    return otp_row


def consume_code(verification: Verification, code: str) -> bool:
    """맞는 인증번호면 한 번만 소비한다. 조건부 원자적 UPDATE로 검증과 폐기를 함께 한다(D46).

    True = 이번 요청이 소비에 성공. False = 아님(틀렸거나, 만료됐거나, 동시 요청에 졌거나).
    False일 때 그 사유를 가려내는 것은 호출하는 쪽의 몫이다(D88).
    """
    consumed = db.session.execute(
        db.update(PhoneOtp)
        .where(
            PhoneOtp.verification_id == verification.id,
            PhoneOtp.code_mac == code_mac(verification.id, code),
            PhoneOtp.code_expires_at > now_utc(),
        )
        .values(code_mac=None, inbox_ciphertext=None)
    )
    return consumed.rowcount == 1


def receive_ci(verification: Verification, phone_row: PhoneVerification, match_token: str) -> str:
    """MC-02로 CI를 받아 보관한다. CI는 A사 밖으로 나가지 않는다.

    통신사 오류는 carrier.CarrierError로 올라간다. 종결(P05) 처리는 호출하는 쪽이 한다.
    """
    ci = carrier.issue_ci(verification.id, match_token)
    phone_row.ci = ci
    phone_row.status = "PASSED"
    phone_row.completed_at = now_utc()
    phone_row.match_token_enc = None  # CI 발급 후 폐기
    log_phone_event(verification.id, "CI_ISSUED")
    return ci


def match_failure(reason: str | None, remaining: int, *, good_status: int) -> tuple[str, int]:
    """D1: 기본(양호)은 사유 구분 없이 같은 메시지·같은 상태 코드를 쓴다.

    양호일 때의 상태 코드는 호출하는 쪽이 정한다 — 인증창은 화면을 다시 그리므로 200,
    위탁사 API는 400. **어느 쪽이든 두 사유가 같은 값을 쓴다**는 것이 D1의 요지다.
    """
    if current_app.config.get("VULN_W14"):
        if reason == carrier.REASON_NOT_SUBSCRIBER:
            return ("등록되지 않은 휴대폰번호입니다.", 404)
        return ("입력하신 성명이 명의자와 다릅니다.", 400)
    return (
        f"성명 또는 휴대폰번호가 일치하지 않습니다. (남은 횟수 {remaining}회)",
        good_status,
    )
