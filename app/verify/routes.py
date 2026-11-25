"""인증창 라우트: IA-02 진입, IA-03 동의, IA-04/06 휴대폰 본인확인, IA-10 취소."""

from __future__ import annotations

import time
from secrets import token_urlsafe

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.common import carrier
from app.common.audit import log_phone_event
from app.common.client_ip import client_ip
from app.common.crypto import sha256_hex
from app.common.log_mask import mask_name, mask_phone
from app.common.phone import (
    code_mac,
    decrypt_match_token,
    encrypt_for_inbox,
    encrypt_match_token,
    generate_code,
    normalize_phone,
    phone_key,
    validate_name,
)
from app.common.stage import (
    SESSION_NAME,
    SESSION_PHONE_NUMBER,
    advance_stage,
    end_session,
    require_stage,
    stage_redirect,
    start_session,
)
from app.common.timeutil import is_expired, kst_isoformat, now_utc, seconds_left
from app.models import (
    CONSENT_TYPES,
    Consent,
    PhoneOtp,
    PhoneVerification,
    TestPhone,
    Verification,
    db,
)
from app.verify.termination import terminate

bp = Blueprint("verify", __name__, url_prefix="/verify")

# 취소는 종결 전 모든 단계에서 받는다(5장)
CANCELLABLE_STAGES = ("CONSENT", "PHONE", "ID_CARD", "ID_CONFIRM", "FACE")


@bp.get("/start/<token>")
def start(token: str):
    """IA-02. 토큰을 1회만 쓰고 서버 세션으로 바꾼 뒤 토큰 없는 주소로 보낸다."""
    expires_at, _, random_part = token.partition(".")
    if not expires_at.isdigit() or not random_part:
        abort(410, description="인증창 주소가 올바르지 않다.")
    if int(time.time()) > int(expires_at):
        abort(410, description="인증창 주소가 만료됐다. 거래소에서 다시 시작한다.")

    # 1회 사용 처리를 원자적 UPDATE로 한다(동시 진입 시 한 번만 성공)
    used = db.session.execute(
        db.update(Verification)
        .where(
            Verification.token_hash == sha256_hex(token),
            Verification.token_used_at.is_(None),
            Verification.status == "PENDING",
        )
        .values(token_used_at=now_utc())
    )
    if used.rowcount != 1:
        db.session.rollback()
        abort(410, description="이미 사용했거나 만료된 인증창 주소다.")
    db.session.commit()

    verification = db.session.scalars(
        db.select(Verification).filter_by(token_hash=sha256_hex(token))
    ).one()

    if is_expired(verification.expires_at):
        terminate(verification, "P03")
        abort(410, description="인증 제한 시간이 지났다. 거래소에서 다시 시작한다.")

    start_session(verification)
    current_app.logger.info("인증창 진입: verification_id=%s", verification.id)
    return stage_redirect(verification)


@bp.get("/consent")
@require_stage("CONSENT")
def consent_page():
    """동의 화면."""
    return render_template(
        "verify/consent.html",
        consent_types=CONSENT_TYPES,
        versions=current_app.config["CONSENT_VERSIONS"],
        seconds_left=int(seconds_left(g.verification.expires_at)),
    )


@bp.post("/consent")
@require_stage("CONSENT")
def consent_submit():
    """IA-03. 동의 4종을 모두 받아야 다음 단계로 간다."""
    verification = g.verification
    versions = current_app.config["CONSENT_VERSIONS"]

    missing = [name for name in CONSENT_TYPES if request.form.get(name) != "on"]
    if missing:
        return (
            render_template(
                "verify/consent.html",
                consent_types=CONSENT_TYPES,
                versions=versions,
                error="필수 동의 4종에 모두 동의해야 진행할 수 있다.",
                seconds_left=int(seconds_left(verification.expires_at)),
            ),
            400,
        )

    # 화면에 표시한 약관 버전과 서버 버전이 다르면 다시 받는다
    for name in CONSENT_TYPES:
        if request.form.get(f"{name}_version") != versions[name]:
            abort(400, description="약관 버전이 바뀌었다. 처음부터 다시 진행한다.")

    agreed_at = now_utc()
    ip = client_ip()
    for name in CONSENT_TYPES:
        db.session.add(
            Consent(
                verification_id=verification.id,
                type=name,
                version=versions[name],
                agreed_at=agreed_at,
                ip=ip,
            )
        )
    advance_stage(verification, "PHONE")
    db.session.commit()
    current_app.logger.info("동의 완료: verification_id=%s", verification.id)
    return stage_redirect(verification)


@bp.get("/phone")
@require_stage("PHONE")
def phone_page():
    """성명·휴대폰번호 입력 화면."""
    return _render_phone_form(g.verification)


@bp.post("/phone/otp")
@require_stage("PHONE")
def phone_otp():
    """IA-04. 명의 대조(MC-01) 후 인증번호를 테스트 수신함으로 발송한다.

    재발송은 resend=1로 보내고 서버 세션의 성명·번호를 재사용한다(D6, 명의 대조는 다시 하지 않는다).
    """
    verification = g.verification
    phone_row = _ensure_phone_row(verification)
    resend = request.form.get("resend") == "1"

    if resend:
        name = session.get(SESSION_NAME)
        number = session.get(SESSION_PHONE_NUMBER)
        if not name or not number:
            return _render_phone_form(
                verification, error="성명과 휴대폰번호를 다시 입력한다.", status=400
            )
    else:
        name = validate_name(request.form.get("name"))
        number = normalize_phone(request.form.get("phone_number"))
        if name is None or number is None:
            return _render_phone_form(
                verification, error="성명과 휴대폰번호 형식을 확인한다.", status=400
            )

        try:
            result = carrier.identity_match(verification.id, name, number)
        except carrier.CarrierError as exc:
            current_app.logger.warning(
                "MC-01 실패: verification_id=%s 사유=%s", verification.id, exc
            )
            terminate(verification, "P05")
            end_session()
            abort(503, description="통신사 응답이 없다. 거래소에서 다시 시작한다.")

        phone_row.match_attempts += 1
        log_phone_event(
            verification.id,
            "IDENTITY_MATCH",
            result_code=None if result.matched else "P01",
            name_mask=mask_name(name),
            phone_mask=mask_phone(number),
        )

        if not result.matched:
            verification.last_error_code = "P01"  # D8
            attempts = phone_row.match_attempts
            db.session.commit()
            if attempts >= current_app.config["MATCH_MAX_ATTEMPTS"]:
                terminate(verification, "P01")
                end_session()
                return redirect(verification.return_url)
            message, status = _match_failure_response(
                result.reason, current_app.config["MATCH_MAX_ATTEMPTS"] - attempts
            )
            return _render_phone_form(
                verification, error=message, status=status, name=name, phone_number=number
            )

        phone_row.match_token_enc = encrypt_match_token(verification.id, result.match_token)
        session[SESSION_NAME] = name
        session[SESSION_PHONE_NUMBER] = number
        db.session.commit()

    otp_row = db.session.get(PhoneOtp, verification.id)
    test_phone = _ensure_test_phone(number)
    blocked = _issue_block_reason(otp_row, test_phone)
    if blocked is not None:
        message = (
            f"인증번호는 건당 {current_app.config['OTP_MAX_ISSUES']}회까지 받을 수 있다."
            if blocked == "MAX_ISSUES"
            else "잠시 후 다시 요청한다(60초 제한)."
        )
        if otp_row is None:
            return _render_phone_form(verification, error=message, status=429)
        return _render_otp_form(verification, otp_row, error=message, status=429)

    otp_row = _issue_code(verification, otp_row, number, test_phone)
    db.session.commit()
    current_app.logger.info(
        "OTP 발송: verification_id=%s issue_no=%s", verification.id, otp_row.issue_no
    )
    return _render_otp_form(verification, otp_row)


@bp.get("/phone/otp")
@require_stage("PHONE")
def otp_page():
    """인증번호 입력 화면(새로고침용). 유효한 인증번호가 없으면 입력 화면으로 돌아간다."""
    otp_row = db.session.get(PhoneOtp, g.verification.id)
    if otp_row is None or otp_row.code_mac is None or is_expired(otp_row.code_expires_at):
        return redirect(url_for("verify.phone_page"))
    return _render_otp_form(g.verification, otp_row)


@bp.post("/phone/confirm")
@require_stage("PHONE")
def phone_confirm():
    """IA-06. 인증번호를 확인하고 CI를 받는다(MC-02) → stage=ID_CARD."""
    verification = g.verification
    phone_row = _ensure_phone_row(verification)
    otp_row = db.session.get(PhoneOtp, verification.id)

    if otp_row is None or otp_row.code_mac is None:
        return _render_phone_form(verification, error="인증번호를 먼저 받는다.", status=400)
    if is_expired(otp_row.code_expires_at):
        return _render_otp_form(
            verification, otp_row, error="인증번호가 만료됐다. 재발송한다.", status=400
        )

    code = (request.form.get("code") or "").strip()
    if not code.isdigit() or len(code) != 6:
        # 형식 오류는 불일치가 아니므로 시도 횟수에 넣지 않는다
        return _render_otp_form(verification, otp_row, error="인증번호 6자리를 입력한다.", status=400)

    # 성공 1회만: 조건부 원자적 UPDATE로 검증과 폐기를 함께 한다(D46)
    consumed = db.session.execute(
        db.update(PhoneOtp)
        .where(
            PhoneOtp.verification_id == verification.id,
            PhoneOtp.code_mac == code_mac(verification.id, code),
            PhoneOtp.code_expires_at > now_utc(),
        )
        .values(code_mac=None, inbox_ciphertext=None)
    )

    if consumed.rowcount != 1:
        db.session.rollback()
        phone_row.otp_attempts += 1
        attempts = phone_row.otp_attempts
        db.session.commit()
        if attempts >= current_app.config["OTP_MAX_ATTEMPTS"]:
            terminate(verification, "P02")
            end_session()
            return redirect(verification.return_url)
        remaining = current_app.config["OTP_MAX_ATTEMPTS"] - attempts
        return _render_otp_form(
            verification,
            otp_row,
            error=f"인증번호가 일치하지 않는다. (남은 횟수 {remaining}회)",
            status=400,
        )

    log_phone_event(verification.id, "OTP_VERIFIED")
    db.session.commit()

    if phone_row.match_token_enc is None:
        current_app.logger.error("대조 토큰이 없다: verification_id=%s", verification.id)
        terminate(verification, "P05")
        end_session()
        abort(503, description="처리 중 문제가 생겼다. 거래소에서 다시 시작한다.")

    try:
        ci = carrier.issue_ci(
            verification.id, decrypt_match_token(verification.id, phone_row.match_token_enc)
        )
    except carrier.CarrierError as exc:
        current_app.logger.warning("MC-02 실패: verification_id=%s 사유=%s", verification.id, exc)
        terminate(verification, "P05")
        end_session()
        abort(503, description="통신사 응답이 없다. 거래소에서 다시 시작한다.")

    phone_row.ci = ci
    phone_row.status = "PASSED"
    phone_row.completed_at = now_utc()
    phone_row.match_token_enc = None  # CI 발급 후 폐기
    log_phone_event(verification.id, "CI_ISSUED")
    advance_stage(verification, "ID_CARD")
    db.session.commit()
    current_app.logger.info("CI 수령: verification_id=%s", verification.id)
    return stage_redirect(verification)


@bp.get("/id-card")
@require_stage("ID_CARD")
def id_card_page():
    """신분증 업로드 화면. 업로드 처리(IA-07)는 5단계에서 붙인다."""
    return render_template(
        "verify/id_card.html",
        name_mask=mask_name(session.get(SESSION_NAME)),
        seconds_left=int(seconds_left(g.verification.expires_at)),
    )


def _ensure_phone_row(verification: Verification) -> PhoneVerification:
    """휴대폰 단계 행을 만들거나 가져온다."""
    row = db.session.get(PhoneVerification, verification.id)
    if row is None:
        row = PhoneVerification(verification_id=verification.id)
        db.session.add(row)
        db.session.flush()
    return row


def _ensure_test_phone(number: str) -> TestPhone:
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


def _issue_block_reason(otp_row: PhoneOtp | None, test_phone: TestPhone) -> str | None:
    """발송을 막아야 하는 이유(D11). 없으면 None."""
    if otp_row is not None:
        if otp_row.issue_no >= current_app.config["OTP_MAX_ISSUES"]:
            return "MAX_ISSUES"
        if not is_expired(otp_row.issued_at + current_app.config["OTP_RESEND_INTERVAL"]):
            return "INTERVAL"
    if test_phone.next_issue_at and not is_expired(test_phone.next_issue_at):
        return "INTERVAL"
    return None


def _issue_code(
    verification: Verification,
    otp_row: PhoneOtp | None,
    number: str,
    test_phone: TestPhone,
) -> PhoneOtp:
    """인증번호를 만들어 검증값·수신함 암호문을 저장한다."""
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
    return otp_row


def _match_failure_response(reason: str | None, remaining: int) -> tuple[str, int]:
    """D1: 기본(양호)은 사유 구분 없이 같은 메시지·같은 상태 코드를 쓴다."""
    if current_app.config.get("VULN_W14"):
        if reason == carrier.REASON_NOT_SUBSCRIBER:
            return ("등록되지 않은 휴대폰번호다.", 404)
        return ("입력한 성명이 명의자와 다르다.", 400)
    return (f"성명 또는 휴대폰번호가 일치하지 않는다. (남은 횟수 {remaining}회)", 200)


def _render_phone_form(
    verification: Verification,
    *,
    error: str | None = None,
    status: int = 200,
    name: str | None = None,
    phone_number: str | None = None,
):
    body = render_template(
        "verify/phone.html",
        error=error,
        name=name,
        phone_number=phone_number,
        seconds_left=int(seconds_left(verification.expires_at)),
    )
    return (body, status) if status != 200 else body


def _render_otp_form(
    verification: Verification,
    otp_row: PhoneOtp,
    *,
    error: str | None = None,
    status: int = 200,
):
    body = render_template(
        "verify/otp.html",
        error=error,
        phone_mask=mask_phone(session.get(SESSION_PHONE_NUMBER)),
        code_expires_at=kst_isoformat(otp_row.code_expires_at),
        resend_at=kst_isoformat(
            otp_row.issued_at + current_app.config["OTP_RESEND_INTERVAL"]
        ),
        issue_no=otp_row.issue_no,
        max_issues=current_app.config["OTP_MAX_ISSUES"],
        seconds_left=int(seconds_left(verification.expires_at)),
    )
    return (body, status) if status != 200 else body


@bp.post("/cancel")
@require_stage(*CANCELLABLE_STAGES)
def cancel():
    """IA-10. 이용자 취소 → P04 종결 후 return_url로 보낸다."""
    verification = g.verification
    return_url = verification.return_url
    terminate(verification, "P04")  # FAILED 이력·웹훅은 terminate가 남긴다
    end_session()
    return redirect(return_url)
