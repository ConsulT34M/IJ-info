"""인증창 라우트: IA-02 진입, IA-03 동의, IA-04/06 휴대폰, IA-07/08 신분증, IA-09 얼굴, IA-10 취소."""

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

from app import mock_mois
from app.common import carrier
from app.common.audit import log_access, log_phone_event
from app.common.ci import ci_matches, ci_mock
from app.common.crypto import aad, encrypt_str
from app.common.decision import bump_face_attempts, require_id_document
from app.common.face import get_face_matcher
from app.common.client_ip import client_ip
from app.common.crypto import sha256_hex
from app.common.log_mask import mask_name, mask_phone, unmasked_logger
from app.common import secrets as secret_store
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
from app.common.rrn import validate_issue_date, validate_rrn
from app.common.stage import (
    SESSION_NAME,
    SESSION_PHONE_NUMBER,
    SESSION_RESULT,
    advance_stage,
    end_session,
    require_stage,
    stage_redirect,
    start_session,
)
from app.common.storage import StorageError, get_storage
from app.common.timeutil import is_expired, kst_isoformat, now_utc, seconds_left
from app.common.upload import validate_image_upload
from app.models import (
    CONSENT_TYPES,
    Consent,
    FaceCheck,
    IdDocument,
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
        abort(410, description="인증 주소가 올바르지 않습니다.")
    if int(time.time()) > int(expires_at):
        abort(410, description="인증 주소의 유효시간이 지났습니다. 이용하시던 서비스에서 다시 시작해 주세요.")

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
        abort(410, description="이미 사용되었거나 유효시간이 지난 주소입니다. 이용하시던 서비스에서 다시 시작해 주세요.")
    db.session.commit()

    verification = db.session.scalars(
        db.select(Verification).filter_by(token_hash=sha256_hex(token))
    ).one()

    if is_expired(verification.expires_at):
        terminate(verification, "P03")
        abort(410, description="인증 제한 시간이 지났습니다. 이용하시던 서비스에서 다시 시작해 주세요.")

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
                error="필수 동의 4가지에 모두 동의하셔야 진행할 수 있습니다.",
                seconds_left=int(seconds_left(verification.expires_at)),
            ),
            400,
        )

    # 화면에 표시한 약관 버전과 서버 버전이 다르면 다시 받는다
    for name in CONSENT_TYPES:
        if request.form.get(f"{name}_version") != versions[name]:
            abort(400, description="약관이 변경되었습니다. 처음부터 다시 진행해 주세요.")

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
                verification, error="성명과 휴대폰번호를 다시 입력해 주세요.", status=400
            )
    else:
        name = validate_name(request.form.get("name"))
        number = normalize_phone(request.form.get("phone_number"))
        if name is None or number is None:
            return _render_phone_form(
                verification, error="성명과 휴대폰번호 형식을 확인해 주세요.", status=400
            )

        try:
            result = carrier.identity_match(verification.id, name, number)
        except carrier.CarrierError as exc:
            current_app.logger.warning(
                "MC-01 실패: verification_id=%s 사유=%s", verification.id, exc
            )
            terminate(verification, "P05")
            end_session()
            abort(503, description="통신사 응답이 없습니다. 잠시 후 이용하시던 서비스에서 다시 시작해 주세요.")

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
            f"인증번호는 건당 {current_app.config['OTP_MAX_ISSUES']}회까지 받을 수 있습니다."
            if blocked == "MAX_ISSUES"
            else "잠시 후 다시 요청해 주세요. (60초 제한)"
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

    if otp_row is None:
        return _render_phone_form(verification, error="인증번호를 먼저 받아 주세요.", status=400)
    if otp_row.code_mac is None:
        # 이미 쓰인 인증번호다. 동시 제출·더블클릭의 진 쪽이므로 틀린 번호가 아니다(D88).
        return _already_used_code(verification)
    if is_expired(otp_row.code_expires_at):
        return _render_otp_form(
            verification, otp_row, error="인증번호 유효시간이 지났습니다. 재발송해 주세요.", status=400
        )

    code = (request.form.get("code") or "").strip()
    if not code.isdigit() or len(code) != 6:
        # 형식 오류는 불일치가 아니므로 시도 횟수에 넣지 않는다
        return _render_otp_form(verification, otp_row, error="인증번호 6자리를 입력해 주세요.", status=400)

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
        # UPDATE가 0행이라고 해서 전부 '틀린 번호'는 아니다(D88). 같은 번호가 동시에
        # 들어오거나 확인 버튼을 두 번 누르면 한쪽만 성공하고, 진 쪽도 여기로 온다.
        # 맞는 번호를 넣고도 시도 횟수가 깎이면 P02로 종결될 수 있어 사유를 가려낸다.
        fresh = db.session.get(PhoneOtp, verification.id)
        if fresh is None or fresh.code_mac is None:
            return _already_used_code(verification)
        if is_expired(fresh.code_expires_at):
            # 검사와 UPDATE 사이에 만료된 경우다. 불일치가 아니므로 횟수를 올리지 않는다.
            return _render_otp_form(
                verification, fresh, error="인증번호 유효시간이 지났습니다. 재발송해 주세요.", status=400
            )

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
            error=f"인증번호가 일치하지 않습니다. (남은 횟수 {remaining}회)",
            status=400,
        )

    log_phone_event(verification.id, "OTP_VERIFIED")
    db.session.commit()

    if phone_row.match_token_enc is None:
        current_app.logger.error("대조 토큰이 없다: verification_id=%s", verification.id)
        terminate(verification, "P05")
        end_session()
        abort(503, description="처리 중 문제가 발생했습니다. 이용하시던 서비스에서 다시 시작해 주세요.")

    try:
        ci = carrier.issue_ci(
            verification.id, decrypt_match_token(verification.id, phone_row.match_token_enc)
        )
    except carrier.CarrierError as exc:
        current_app.logger.warning("MC-02 실패: verification_id=%s 사유=%s", verification.id, exc)
        terminate(verification, "P05")
        end_session()
        abort(503, description="통신사 응답이 없습니다. 잠시 후 이용하시던 서비스에서 다시 시작해 주세요.")

    phone_row.ci = ci
    phone_row.status = "PASSED"
    phone_row.completed_at = now_utc()
    phone_row.match_token_enc = None  # CI 발급 후 폐기
    log_phone_event(verification.id, "CI_ISSUED")
    advance_stage(verification, "ID_CARD")
    db.session.commit()
    current_app.logger.info("CI 수령: verification_id=%s", verification.id)
    return stage_redirect(verification)



def _already_used_code(verification: Verification):
    """이미 소비된 인증번호로 다시 들어온 요청(D88).

    맞는 번호를 두 번 보낸 것이지 틀린 번호가 아니므로 시도 횟수를 올리지 않는다.
    먼저 도착한 요청이 아직 다음 단계로 못 올렸을 수 있어 현재 단계로 돌려보낸다.
    """
    current_app.logger.info("이미 사용된 인증번호 재제출: verification_id=%s", verification.id)
    if verification.is_finished:
        abort(409)
    return stage_redirect(verification)


@bp.get("/id-card")
@require_stage("ID_CARD")
def id_card_page():
    """신분증 사진 등록 화면."""
    _require_ci(g.verification)
    return _render_id_card(g.verification)


@bp.post("/id-card")
@require_stage("ID_CARD")
def id_card_submit():
    """IA-07. 신분증 이미지를 받아 얼굴 1개를 확인하고 저장한다.

    W-12: 요청마다 CI 수령 완료를 확인한다.
    D41: 이 시점에 id_documents 행을 만들어 이미지가 DB로 추적되게 한다.
    """
    verification = g.verification
    _require_ci(verification)

    upload = validate_image_upload(
        request.files.get("image"),
        max_bytes=current_app.config["UPLOAD_MAX_BYTES"],
        allowed_extensions=current_app.config["UPLOAD_ALLOWED_EXTENSIONS"],
    )
    if not upload.ok:
        current_app.logger.info(
            "신분증 업로드 거부: verification_id=%s 사유=%s", verification.id, upload.error
        )
        return _fail_id_card(verification, _UPLOAD_MESSAGES[upload.error])

    face_count = get_face_matcher().detect_face_count(upload.data, hint=upload.hint)
    if face_count != 1:
        current_app.logger.info(
            "신분증 얼굴 검출 실패: verification_id=%s count=%s", verification.id, face_count
        )
        return _fail_id_card(verification, "신분증 사진에 얼굴이 한 명만 보이도록 다시 촬영해 주세요.")

    storage = get_storage()
    document = db.session.get(IdDocument, verification.id)
    if document is None:
        document = IdDocument(verification_id=verification.id, name=session[SESSION_NAME])
        db.session.add(document)

    previous_key = document.s3_key
    document.s3_key = storage.save(upload.data, upload.extension)
    document.deleted_at = None
    if previous_key:
        storage.delete(previous_key)  # D41: 재업로드 시 이전 파일은 즉시 지운다

    advance_stage(verification, "ID_CONFIRM")
    db.session.commit()
    current_app.logger.info("신분증 이미지 등록: verification_id=%s", verification.id)
    return stage_redirect(verification)


@bp.get("/id-confirm")
@require_stage("ID_CONFIRM")
def id_confirm_page():
    """신분증 정보 입력 화면. 성명은 서버 세션 값으로 고정한다(W-16)."""
    _require_ci(g.verification)
    return _render_id_confirm(g.verification)


@bp.post("/id-confirm")
@require_stage("ID_CONFIRM")
def id_confirm_submit():
    """IA-08. 체크섬 → X-01 CI 대조 → 모의 진위확인 순서로 본다.

    요청 본문의 성명은 무시하고 서버 세션 값을 쓴다(W-16).
    """
    verification = g.verification
    phone = _require_ci(verification)
    document = db.session.get(IdDocument, verification.id)
    if document is None or not document.s3_key:
        abort(403, description="신분증 사진을 먼저 등록해 주세요.")

    name = session.get(SESSION_NAME)
    if not name:
        abort(403, description="처음부터 다시 진행해 주세요.")

    rrn_check = validate_rrn(_submitted_rrn(request.form))
    if not rrn_check.ok:
        current_app.logger.info(
            "주민번호 검사 실패: verification_id=%s 사유=%s", verification.id, rrn_check.error
        )
        return _fail_id_confirm(verification, "E02", "주민등록번호를 다시 확인해 주세요.")

    issue_check = validate_issue_date(request.form.get("issue_date"), rrn_check.birth_date)
    if not issue_check.ok:
        current_app.logger.info(
            "발급일자 검사 실패: verification_id=%s 사유=%s", verification.id, issue_check.error
        )
        return _fail_id_confirm(verification, "E02", "발급일자를 다시 확인해 주세요.")

    document.rrn_enc = encrypt_str(
        secret_store.get_key("ekyc/rrn-key"),
        rrn_check.rrn,
        aad("id_documents", "rrn_enc", verification.id),
    )
    document.birth_date = rrn_check.birth_date
    document.issue_date = issue_check.issue_date

    # X-01: 입력 주민번호로 계산한 CI와 휴대폰 본인확인으로 받은 CI를 대조한다(W-13)
    computed_ci = ci_mock(rrn_check.rrn, secret_store.get_key("ekyc/ci-key"))
    if not ci_matches(computed_ci, phone.ci):
        document.ci_matched = False
        log_access(
            "system",
            "CI_MISMATCH",
            actor_id=str(verification.client_id),
            target_id=str(verification.id),
            ip=client_ip(),
        )
        db.session.commit()
        current_app.logger.warning("X-01 CI 불일치: verification_id=%s", verification.id)
        terminate(verification, "X01")  # 재시도 없이 즉시 종결
        end_session()
        return redirect(verification.return_url)

    document.ci_matched = True

    if not mock_mois.verify(name, rrn_check.rrn, issue_check.issue_date):
        document.mois_matched = False
        current_app.logger.info("진위확인 불일치: verification_id=%s", verification.id)
        return _fail_id_confirm(verification, "E03", "신분증 정보가 확인되지 않습니다.")

    document.mois_matched = True
    advance_stage(verification, "FACE")
    db.session.commit()
    current_app.logger.info("신분증 확인 완료: verification_id=%s", verification.id)
    return stage_redirect(verification)


@bp.get("/face")
@require_stage("FACE")
def face_page():
    """얼굴 사진 등록 화면."""
    _require_id_document(g.verification)
    return _render_face(g.verification)


@bp.post("/face")
@require_stage("FACE", vuln_flag="VULN_W09")
def face_submit():
    """IA-09. 신분증 사진과 셀카를 대조해 최종 판정한다.

    D2: 최종 판정은 플래그와 무관하게 항상 `id_documents.ci_matched IS TRUE`를 요구한다.
    VULN_W09를 켜면 stage 검사(FACE)와 진위확인 통과 확인만 빠진다.
    """
    verification = g.verification
    _require_ci(verification)
    document = _require_id_document(verification)

    upload = validate_image_upload(
        request.files.get("image"),
        max_bytes=current_app.config["UPLOAD_MAX_BYTES"],
        allowed_extensions=current_app.config["UPLOAD_ALLOWED_EXTENSIONS"],
    )
    if not upload.ok:
        current_app.logger.info(
            "얼굴 사진 거부: verification_id=%s 사유=%s", verification.id, upload.error
        )
        return _fail_face(verification, "E01", _UPLOAD_MESSAGES[upload.error])

    storage = get_storage()
    try:
        id_card_image = storage.load(document.s3_key)
    except StorageError:
        current_app.logger.error(
            "신분증 이미지를 읽을 수 없다: verification_id=%s", verification.id
        )
        abort(500)

    # 시도마다 행을 남긴다. 파일은 판정 직후 지운다.
    check = FaceCheck(verification_id=verification.id, s3_key=storage.save(upload.data, upload.extension))
    db.session.add(check)

    comparison = get_face_matcher().compare_faces(
        id_card_image,
        upload.data,
        hint=upload.hint,
        threshold=current_app.config["FACE_SIMILARITY_THRESHOLD"],
    )
    check.face_count = comparison.face_count
    check.similarity = comparison.similarity
    check.matched = comparison.matched

    storage.delete(check.s3_key)  # 판정 즉시 삭제
    check.s3_key = None
    check.deleted_at = now_utc()
    db.session.commit()

    if comparison.face_count != 1:
        current_app.logger.info(
            "얼굴 검출 실패: verification_id=%s count=%s", verification.id, comparison.face_count
        )
        return _fail_face(verification, "E04", "얼굴이 한 명만 보이는 사진으로 다시 올려 주세요.")

    if not comparison.matched:
        current_app.logger.info("얼굴 유사도 미달: verification_id=%s", verification.id)
        return _fail_face(verification, "E05", "신분증 사진과 일치하지 않습니다.")

    current_app.logger.info("최종 판정 성공: verification_id=%s", verification.id)
    return _finish_with_result(verification, "OK")


@bp.get("/result")
def result_page():
    """결과 화면. 세션에는 판정 결과와 돌아갈 주소만 둔다(D64)."""
    result = session.get(SESSION_RESULT)
    if not result:
        abort(403, description="표시할 결과가 없습니다.")
    return render_template("verify/result.html", **result)


_UPLOAD_MESSAGES = {
    "EMPTY": "신분증 사진을 선택해 주세요.",
    "EXTENSION": "jpg 또는 png 파일만 올릴 수 있습니다.",
    "SIZE": "5MB 이하 파일만 올릴 수 있습니다.",
    "MAGIC": "이미지 파일이 아닙니다. jpg 또는 png로 다시 올려 주세요.",
    None: "신분증 사진을 다시 올려 주세요.",
}


def _require_id_document(verification: Verification) -> IdDocument:
    """얼굴 단계 요구사항(D2). 서버 간 API(IA-22)와 같은 함수를 쓴다."""
    return require_id_document(verification)


def _finish_with_result(verification: Verification, reason_code: str):
    """최종 판정 후 결과 화면으로 보낸다."""
    return_url = verification.return_url
    terminate(verification, reason_code)
    status = verification.status
    end_session()
    session[SESSION_RESULT] = {
        "status": status,
        "reason_code": reason_code,
        "return_url": return_url,
    }
    return redirect(url_for("verify.result_page"))


def _require_ci(verification: Verification) -> PhoneVerification:
    """W-12: 신분증 단계 요청마다 CI 수령 완료를 확인한다."""
    phone = db.session.get(PhoneVerification, verification.id)
    if phone is None or phone.status != "PASSED" or not phone.ci:
        current_app.logger.warning(
            "CI 미수령 상태의 신분증 단계 요청: verification_id=%s", verification.id
        )
        abort(403, description="휴대폰 본인확인을 먼저 완료해 주세요.")
    return phone


def _bump_face_attempts(verification: Verification, code: str) -> int:
    """얼굴 단계 시도 합산(D8, D10). 서버 간 API와 같은 함수를 쓴다."""
    return bump_face_attempts(verification, code)


def _fail_face_step(verification: Verification, code: str, message: str, renderer):
    """시도 횟수를 올리고, 3회에 도달하면 E06으로 종결한다(D10)."""
    attempts = _bump_face_attempts(verification, code)
    limit = current_app.config["FACE_MAX_ATTEMPTS"]
    if attempts >= limit:
        current_app.logger.info(
            "얼굴 단계 시도 초과: verification_id=%s 마지막 코드=%s", verification.id, code
        )
        terminate(verification, "E06")
        end_session()
        return redirect(verification.return_url)
    remaining = limit - attempts
    return renderer(f"{message} (남은 시도 {remaining}회)")


def _fail_id_card(verification: Verification, message: str):
    return _fail_face_step(
        verification,
        "E01",
        message,
        lambda text: (_render_id_card(verification, error=text), 400),
    )


def _fail_face(verification: Verification, code: str, message: str):
    return _fail_face_step(
        verification,
        code,
        message,
        lambda text: (_render_face(verification, error=text), 400),
    )


def _render_face(verification: Verification, *, error: str | None = None):
    return render_template(
        "verify/face.html",
        error=error,
        max_mb=current_app.config["UPLOAD_MAX_BYTES"] // (1024 * 1024),
        seconds_left=int(seconds_left(verification.expires_at)),
    )


def _fail_id_confirm(verification: Verification, code: str, message: str):
    return _fail_face_step(
        verification,
        code,
        message,
        lambda text: (_render_id_confirm(verification, error=text), 400),
    )


def _render_id_card(verification: Verification, *, error: str | None = None):
    return render_template(
        "verify/id_card.html",
        error=error,
        name_mask=mask_name(session.get(SESSION_NAME)),
        max_mb=current_app.config["UPLOAD_MAX_BYTES"] // (1024 * 1024),
        seconds_left=int(seconds_left(verification.expires_at)),
    )


def _submitted_rrn(form) -> str | None:
    """F-05: 화면은 앞 6자리·뒤 7자리로 나눠 받고(뒤는 password) 서버에서 합친다(D79)."""
    front = (form.get("rrn_front") or "").strip()
    back = (form.get("rrn_back") or "").strip()
    if front or back:
        return f"{front}{back}"
    return form.get("rrn")


def _render_id_confirm(verification: Verification, *, error: str | None = None):
    return render_template(
        "verify/id_confirm.html",
        error=error,
        name=session.get(SESSION_NAME),
        seconds_left=int(seconds_left(verification.expires_at)),
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

    if current_app.config.get("VULN_W17"):
        # VULN_W17: 마스킹 필터를 거치지 않는 로거로 인증번호·번호 원문을 남긴다(실습 전용)
        unmasked_logger().debug(
            "otp issued verification_id=%s phone_number=%s code=%s",
            verification.id,
            number,
            code,
        )

    return otp_row


def _match_failure_response(reason: str | None, remaining: int) -> tuple[str, int]:
    """D1: 기본(양호)은 사유 구분 없이 같은 메시지·같은 상태 코드를 쓴다."""
    if current_app.config.get("VULN_W14"):
        if reason == carrier.REASON_NOT_SUBSCRIBER:
            return ("등록되지 않은 휴대폰번호입니다.", 404)
        return ("입력하신 성명이 명의자와 다릅니다.", 400)
    return (f"성명 또는 휴대폰번호가 일치하지 않습니다. (남은 횟수 {remaining}회)", 200)


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
