"""IA-21 / IA-22: 위탁사가 인증 화면을 직접 만들 때 쓰는 서버 간 경로(D87).

기존 인증창(IA-02~IA-10)은 그대로 둔다. IA-01에 `mode="DIRECT"`를 주면 auth_url 없이
verification_id만 받고, 아래 두 엔드포인트로 신분증·얼굴을 제출한다.

- 이미지는 JSON 본문에 base64로 담는다. 서명 규칙(X-Timestamp 바이트 + 본문 바이트)을
  그대로 쓸 수 있어 multipart보다 양쪽 구현을 맞추기 쉽다.
- 휴대폰 본인확인은 위탁사가 하고, 그때 받은 CI를 IA-21에 함께 보낸다. A사는 그 CI와
  제출된 주민번호로 계산한 CI를 대조한다(X-01). CI 없이는 받지 않는다 — 없으면
  "휴대폰 명의자와 신분증 명의자가 같다"를 A사가 보장할 수 없기 때문이다.
- 판정이 확정되면(OK·X01·E06) 200에 결과 본문을 싣고 웹훅도 보낸다.
  다시 제출하면 되는 실패(E01~E05)는 400이다.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime

from flask import abort, current_app, g, jsonify, request

from app.api.routes import bp
from app.api.webhook import build_result_payload
from app.common import secrets as secret_store
from app.common.audit import log_access
from app.common.ci import ci_matches, ci_mock
from app.common.client_ip import client_ip
from app.common.crypto import aad, encrypt_str
from app.common.decision import (
    attempts_exhausted,
    attempts_left,
    bump_face_attempts,
    require_id_document,
)
from app.common.face import get_face_matcher
from app.api.auth import require_client_auth
from app.common import carrier
from app.common.audit import log_phone_event
from app.common.log_mask import mask_name, mask_phone
from app.common.phone import (
    decrypt_match_token,
    encrypt_match_token,
    normalize_phone,
    phone_key,
    validate_name,
)
from app.common.phone_flow import (
    consume_code,
    ensure_phone_row,
    ensure_test_phone,
    issue_block_reason,
    issue_code,
    match_failure,
    receive_ci,
)
from app.common.stage import advance_stage
from app.common.timeutil import kst_isoformat
from app.common.rrn import validate_issue_date, validate_rrn
from app.common.storage import StorageError, get_storage
from app.common.timeutil import is_expired, now_utc
from app.common.upload import validate_image_upload
from app.mock_mois import verify as mois_verify
from app.models import (
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

CI_LENGTH = 88
MAX_FILENAME = 120

UPLOAD_MESSAGES = {
    "EMPTY": "이미지가 비어 있습니다.",
    "EXTENSION": "jpg 또는 png 파일만 올릴 수 있습니다.",
    "SIZE": "5MB 이하 파일만 올릴 수 있습니다.",
    "MAGIC": "이미지 파일이 아닙니다. jpg 또는 png로 다시 올려 주세요.",
    None: "이미지를 다시 올려 주세요.",
}


class _Base64Upload:
    """base64로 받은 이미지를 W-04 검사기(validate_image_upload)가 읽을 수 있게 감싼다."""

    def __init__(self, data: bytes, filename: str):
        self._data = data
        self.filename = filename

    def read(self, size: int = -1) -> bytes:
        return self._data if size < 0 else self._data[:size]


# --------------------------------------------------------------------- 공통


def _json_body() -> dict:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON 본문이 필요합니다.")
    return payload


def _load_direct(verification_id) -> Verification:
    """DIRECT 건을 꺼낸다. 소유 확인은 플래그와 무관하게 항상 한다."""
    verification = db.session.get(Verification, verification_id)
    # 제출 경로에서는 VULN_W08을 적용하지 않는다. 읽기(IA-12)와 달리 남의 건을
    # 고쳐 쓸 수 있게 되면 플래그 하나가 통제 전체를 무너뜨린다.
    if verification is None or verification.client_id != g.client.id:
        abort(404, description="해당 건을 찾을 수 없습니다.")
    if verification.mode != "DIRECT":
        abort(403, description="인증창 방식으로 만든 건입니다. 인증 화면에서 진행해 주세요.")
    if verification.status != "PENDING":
        abort(409, description="이미 종료된 인증입니다. 새로 요청해 주세요.")
    if is_expired(verification.expires_at):
        terminate(verification, "P03")
        abort(410, description="인증 제한 시간이 지났습니다. 새로 요청해 주세요.")
    return verification


def _decode_image(payload: dict):
    """본문의 image(base64)와 filename을 W-04 검사까지 통과시킨다."""
    raw = payload.get("image")
    filename = payload.get("filename")
    if not isinstance(raw, str) or not raw:
        return None, "EMPTY"
    if not isinstance(filename, str) or not filename or len(filename) > MAX_FILENAME:
        return None, "EXTENSION"

    max_bytes = current_app.config["UPLOAD_MAX_BYTES"]
    if len(raw) > (max_bytes * 4 // 3) + 16:  # 디코딩 전에 끊어 낸다
        return None, "SIZE"
    try:
        data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return None, "MAGIC"

    check = validate_image_upload(
        _Base64Upload(data, filename),
        max_bytes=max_bytes,
        allowed_extensions=current_app.config["UPLOAD_ALLOWED_EXTENSIONS"],
    )
    return (check, None) if check.ok else (None, check.error)


def _retry_response(verification: Verification, code: str, message: str):
    """다시 제출하면 되는 실패(E01~E05). 상한에 닿으면 E06으로 종결한다(D10)."""
    attempts = bump_face_attempts(verification, code)
    if attempts_exhausted(attempts):
        current_app.logger.info(
            "얼굴 단계 시도 초과: verification_id=%s 마지막 코드=%s", verification.id, code
        )
        terminate(verification, "E06")
        return _result_response(verification)
    return (
        jsonify(
            verification_id=str(verification.id),
            mode=verification.mode,
            stage=verification.stage,
            passed=False,
            reason_code=code,
            message=message,
            attempts_left=attempts_left(attempts),
        ),
        400,
    )


def _result_response(verification: Verification, status_code: int = 200):
    """판정이 확정된 건의 결과 본문. 웹훅과 같은 모양이다(7장)."""
    payload = build_result_payload(verification)
    payload["mode"] = verification.mode
    return jsonify(payload), status_code


# --------------------------------------------------------------------- IA-21


@bp.post("/verifications/<uuid:verification_id>/id-card")
@require_client_auth
def submit_id_card(verification_id):
    """IA-21. 신분증 이미지와 정보를 한 번에 받아 체크섬 → X-01 → 진위확인까지 본다."""
    verification = _load_direct(verification_id)
    if verification.stage != "ID_CARD":
        abort(403, description="지금 단계에서는 진행할 수 없는 요청입니다.")

    payload = _json_body()

    name = validate_name(payload.get("name"))
    if name is None:
        abort(400, description="name이 필요합니다.")

    # CI는 A사가 휴대폰 단계(IA-24)에서 통신사에게 받아 보관한 값만 쓴다(D98).
    # 위탁사가 보내는 CI는 받지 않는다 — 받으면 X-01이 "같은 키로 같은 주민번호를
    # 두 번 계산해 비교하는" 항등식이 되어 검사 구실을 못 한다.
    if "ci" in payload:
        abort(400, description="ci는 더 이상 받지 않습니다. 휴대폰 본인확인(IA-23·IA-24)을 거쳐 주세요.")
    phone_row = db.session.get(PhoneVerification, verification.id)
    if phone_row is None or phone_row.status != "PASSED" or not phone_row.ci:
        abort(409, description="휴대폰 본인확인을 먼저 끝내 주세요.")
    ci = phone_row.ci

    upload, upload_error = _decode_image(payload)
    if upload is None:
        current_app.logger.info(
            "신분증 업로드 거부: verification_id=%s 사유=%s", verification.id, upload_error
        )
        return _retry_response(verification, "E01", UPLOAD_MESSAGES[upload_error])

    if get_face_matcher().detect_face_count(upload.data, hint=upload.hint) != 1:
        current_app.logger.info("신분증 얼굴 검출 실패: verification_id=%s", verification.id)
        return _retry_response(
            verification, "E01", "신분증 사진에 얼굴이 한 명만 보이도록 다시 촬영해 주세요."
        )

    rrn_check = validate_rrn(payload.get("rrn"))
    if not rrn_check.ok:
        current_app.logger.info(
            "주민번호 검사 실패: verification_id=%s 사유=%s", verification.id, rrn_check.error
        )
        return _retry_response(verification, "E02", "주민등록번호를 다시 확인해 주세요.")

    issue_check = validate_issue_date(payload.get("issue_date"), rrn_check.birth_date)
    if not issue_check.ok:
        current_app.logger.info(
            "발급일자 검사 실패: verification_id=%s 사유=%s", verification.id, issue_check.error
        )
        return _retry_response(verification, "E02", "발급일자를 다시 확인해 주세요.")

    _record_consents(verification, payload.get("consents"))

    storage = get_storage()
    document = db.session.get(IdDocument, verification.id)
    if document is None:
        document = IdDocument(verification_id=verification.id, name=name)
        db.session.add(document)
    else:
        document.name = name

    previous_key = document.s3_key
    document.s3_key = storage.save(upload.data, upload.extension)
    document.deleted_at = None
    if previous_key:
        storage.delete(previous_key)  # D41: 재제출 시 이전 파일은 즉시 지운다

    document.rrn_enc = encrypt_str(
        secret_store.get_key("ekyc/rrn-key"),
        rrn_check.rrn,
        aad("id_documents", "rrn_enc", verification.id),
    )
    document.birth_date = rrn_check.birth_date
    document.issue_date = issue_check.issue_date

    # X-01: 통신사가 발급한 CI(휴대폰 명의자)와 제출된 주민번호로 계산한 CI를 대조한다(W-13)
    if not ci_matches(ci_mock(rrn_check.rrn, secret_store.get_key("ekyc/ci-key")), ci):
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
        return _result_response(verification)

    document.ci_matched = True

    if not mois_verify(name, rrn_check.rrn, issue_check.issue_date):
        document.mois_matched = False
        db.session.commit()
        current_app.logger.info("진위확인 불일치: verification_id=%s", verification.id)
        return _retry_response(verification, "E03", "신분증 정보가 확인되지 않습니다.")

    document.mois_matched = True
    verification.stage = "FACE"
    db.session.commit()
    current_app.logger.info("신분증 확인 완료(IA-21): verification_id=%s", verification.id)
    return (
        jsonify(
            verification_id=str(verification.id),
            mode=verification.mode,
            stage=verification.stage,
            passed=True,
            reason_code=None,
            attempts_left=attempts_left(verification.face_attempts),
        ),
        200,
    )


# --------------------------------------------------------------------- IA-22


@bp.post("/verifications/<uuid:verification_id>/face")
@require_client_auth
def submit_face(verification_id):
    """IA-22. 얼굴 사진을 신분증 사진과 대조해 최종 판정한다."""
    verification = _load_direct(verification_id)
    # 양호 기본값: FACE 단계에서만 받는다. VULN_W09를 켜면 단계 검사가 빠진다(D2).
    if verification.stage != "FACE" and not current_app.config.get("VULN_W09"):
        abort(403, description="지금 단계에서는 진행할 수 없는 요청입니다.")

    document = require_id_document(verification)
    payload = _json_body()

    upload, upload_error = _decode_image(payload)
    if upload is None:
        current_app.logger.info(
            "얼굴 사진 거부: verification_id=%s 사유=%s", verification.id, upload_error
        )
        return _retry_response(verification, "E01", UPLOAD_MESSAGES[upload_error])

    storage = get_storage()
    try:
        id_card_image = storage.load(document.s3_key)
    except StorageError:
        current_app.logger.error(
            "신분증 이미지를 읽을 수 없다: verification_id=%s", verification.id
        )
        abort(500)

    check = FaceCheck(
        verification_id=verification.id, s3_key=storage.save(upload.data, upload.extension)
    )
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
        current_app.logger.info("얼굴 검출 실패: verification_id=%s", verification.id)
        return _retry_response(
            verification, "E04", "얼굴이 한 명만 보이는 사진으로 다시 올려 주세요."
        )
    if not comparison.matched:
        current_app.logger.info("얼굴 유사도 미달: verification_id=%s", verification.id)
        return _retry_response(verification, "E05", "신분증 사진과 일치하지 않습니다.")

    current_app.logger.info("최종 판정 성공(IA-22): verification_id=%s", verification.id)
    terminate(verification, "OK")
    return _result_response(verification)


# --------------------------------------------------------------------- 동의


def _record_consents(verification: Verification, raw) -> None:
    """위탁사 화면에서 받은 동의를 증적으로 남긴다(선택).

    화면이 위탁사에 있으므로 동의 자체는 위탁사가 받는다. 수탁사도 "무엇에 동의받고
    넘어온 건인지"를 남겨야 하므로 전달받은 값을 그대로 기록한다. ip는 전달한
    위탁사 서버 주소이지 이용자 주소가 아니다(D87).
    """
    if not isinstance(raw, list) or not raw:
        return
    if db.session.scalars(
        db.select(Consent).filter_by(verification_id=verification.id).limit(1)
    ).first():
        return  # 재제출 때 중복 기록하지 않는다

    versions = current_app.config["CONSENT_VERSIONS"]
    ip = client_ip()
    for item in raw:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind not in versions:
            continue
        agreed_at = _parse_time(item.get("agreed_at")) or now_utc()
        db.session.add(
            Consent(
                verification_id=verification.id,
                type=kind,
                version=str(item.get("version") or versions[kind])[:20],
                agreed_at=agreed_at,
                ip=ip,
            )
        )


def _parse_time(value) -> datetime | None:
    """ISO 8601 문자열을 naive UTC로. 못 읽으면 None."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(tz=None).replace(tzinfo=None)
    return parsed


# ----------------------------------------------------------- IA-23 / IA-24
#
# 휴대폰 본인확인을 A사로 되돌린다(D98).
#
# 전에는 위탁사가 인증번호를 만들고 검증한 뒤 CI까지 계산해서 IA-21에 실어 보냈다.
# 그러면 X-01(휴대폰 명의자 = 신분증 명의자)이 **구조적으로 항상 통과한다** —
# 대조할 두 값이 같은 키·같은 주민번호에서 나오기 때문이다. 검사가 아니라 항등식이다.
# 거래소 요구사항 정의서 FR-001도 "A는 이름·휴대폰번호를 대조하고 인증번호를 검증해야
# 한다"로 돼 있다.
#
# 그래서 CI 공유키는 A사와 모의 통신사만 갖는다. 위탁사는 CI를 보지도 만들지도 않는다.
#
# 인증번호를 **만드는 주체도 A사다.** 모의 통신사는 명의 대조(MC-01)와 CI 발급(MC-02)만
# 한다. 실제 휴대폰 본인확인에서도 본인확인기관이 발송 주체이고 통신사는 명의를 확인해
# 준다. 위탁사는 인증번호를 받지 못한다 — 받으면 그 자체가 오라클이다.


def _phone_stage(verification: Verification):
    """휴대폰 단계에서만 받는다. 이미 지났으면 무엇이 잘못됐는지 알려 준다."""
    if verification.stage == "PHONE":
        return
    if verification.stage in ("ID_CARD", "ID_CONFIRM", "FACE", "DONE"):
        abort(409, description="휴대폰 본인확인이 이미 끝난 건입니다.")
    abort(403, description="지금 단계에서 받을 수 없는 요청입니다.")


@bp.post("/verifications/<uuid:verification_id>/phone/otp")
@require_client_auth
def request_phone_otp(verification_id):
    """IA-23. 명의 대조(MC-01) 후 인증번호를 발송한다.

    응답에 인증번호를 넣지 않는다. 이용자는 본인 휴대폰(모의 PASS 앱 / 테스트 수신함)에서
    확인한다. 재발송은 resend=true로 보내고 직전 성명·번호를 재사용한다(D6).
    """
    verification = _load_direct(verification_id)
    _phone_stage(verification)
    payload = _json_body()
    phone_row = ensure_phone_row(verification)
    resend = payload.get("resend") is True

    otp_row = db.session.get(PhoneOtp, verification.id)

    name = validate_name(payload.get("name"))
    number = normalize_phone(payload.get("phone_number"))
    if name is None or number is None:
        abort(400, description="성명과 휴대폰번호 형식을 확인해 주세요.")

    if resend:
        # D6: 재발송은 명의 대조를 다시 하지 않는다. 번호 원문을 저장하지 않으므로
        # 위탁사가 같은 값을 다시 보내고, A사는 phone_key로 같은 번호인지만 확인한다.
        if otp_row is None or phone_row.match_token_enc is None:
            abort(409, description="먼저 성명과 휴대폰번호로 인증번호를 요청해 주세요.")
        if otp_row.phone_key != phone_key(number):
            abort(400, description="처음 보낸 휴대폰번호와 다릅니다.")
    else:
        try:
            result = carrier.identity_match(verification.id, name, number)
        except carrier.CarrierError as exc:
            current_app.logger.warning("MC-01 실패: verification_id=%s 사유=%s", verification.id, exc)
            terminate(verification, "P05")
            abort(503, description="통신사 응답이 없습니다. 잠시 후 다시 시작해 주세요.")

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
            maximum = current_app.config["MATCH_MAX_ATTEMPTS"]
            db.session.commit()
            if attempts >= maximum:
                terminate(verification, "P01")
                return _result_response(verification, 409)
            message, status = match_failure(result.reason, maximum - attempts, good_status=400)
            return (
                jsonify(
                    verification_id=str(verification.id),
                    stage=verification.stage,
                    passed=False,
                    reason_code="P01",
                    message=message,
                    attempts_left=maximum - attempts,
                ),
                status,
            )

        phone_row.match_token_enc = encrypt_match_token(verification.id, result.match_token)
        db.session.commit()

    test_phone = ensure_test_phone(number)
    blocked = issue_block_reason(otp_row, test_phone)
    if blocked is not None:
        message = (
            f"인증번호는 건당 {current_app.config['OTP_MAX_ISSUES']}회까지 받을 수 있습니다."
            if blocked == "MAX_ISSUES"
            else "잠시 후 다시 요청해 주세요. (60초 제한)"
        )
        abort(429, description=message)

    otp_row = issue_code(verification, otp_row, number, test_phone)
    db.session.commit()
    current_app.logger.info(
        "IA-23 인증번호 발송: verification_id=%s issue_no=%s", verification.id, otp_row.issue_no
    )
    return (
        jsonify(
            verification_id=str(verification.id),
            stage=verification.stage,
            phone_mask=mask_phone(number),
            code_expires_at=kst_isoformat(otp_row.code_expires_at),
            resend_available_at=kst_isoformat(
                otp_row.issued_at + current_app.config["OTP_RESEND_INTERVAL"]
            ),
            issues_left=current_app.config["OTP_MAX_ISSUES"] - otp_row.issue_no,
            message="이용자 휴대폰으로 인증번호를 보냈습니다.",
        ),
        200,
    )


@bp.post("/verifications/<uuid:verification_id>/phone/confirm")
@require_client_auth
def confirm_phone_otp(verification_id):
    """IA-24. 인증번호를 확인하고 CI를 받는다(MC-02) → stage=ID_CARD.

    CI는 응답에 넣지 않는다. A사 안에만 둔다.
    """
    verification = _load_direct(verification_id)
    payload = _json_body()
    phone_row = ensure_phone_row(verification)

    # 이미 끝난 휴대폰 단계에 다시 오는 요청은 멱등으로 받는다. 위탁사가 응답을 못 받고
    # 재전송하는 경우다 — 여기서 409를 내면 멀쩡한 건이 막힌다. 시도 횟수는 올리지 않는다.
    if verification.stage != "PHONE" and phone_row.status == "PASSED":
        return jsonify(
            verification_id=str(verification.id),
            stage=verification.stage,
            passed=True,
            phone="PASSED",
            message="휴대폰 본인확인은 이미 끝났습니다.",
        )
    _phone_stage(verification)
    otp_row = db.session.get(PhoneOtp, verification.id)

    if otp_row is None:
        abort(409, description="인증번호를 먼저 요청해 주세요.")

    code = str(payload.get("code") or "").strip()
    if not code.isdigit() or len(code) != 6:
        # 형식 오류는 불일치가 아니므로 시도 횟수에 넣지 않는다
        abort(400, description="인증번호 6자리를 보내 주세요.")

    if not consume_code(verification, code):
        db.session.rollback()
        fresh = db.session.get(PhoneOtp, verification.id)
        if fresh is None or fresh.code_mac is None:
            # 이미 쓰인 번호다(동시 제출). 틀린 번호가 아니므로 횟수를 올리지 않는다(D88).
            abort(409, description="이미 사용된 인증번호입니다. 잠시 후 상태를 확인해 주세요.")
        if is_expired(fresh.code_expires_at):
            abort(400, description="인증번호 유효시간이 지났습니다. 재발송해 주세요.")

        phone_row.otp_attempts += 1
        attempts = phone_row.otp_attempts
        maximum = current_app.config["OTP_MAX_ATTEMPTS"]
        db.session.commit()
        if attempts >= maximum:
            terminate(verification, "P02")
            return _result_response(verification, 409)
        return (
            jsonify(
                verification_id=str(verification.id),
                stage=verification.stage,
                passed=False,
                reason_code="P02",
                message=f"인증번호가 일치하지 않습니다. (남은 횟수 {maximum - attempts}회)",
                attempts_left=maximum - attempts,
            ),
            400,
        )

    log_phone_event(verification.id, "OTP_VERIFIED")
    db.session.commit()

    if phone_row.match_token_enc is None:
        current_app.logger.error("대조 토큰이 없다: verification_id=%s", verification.id)
        terminate(verification, "P05")
        abort(503, description="처리 중 문제가 발생했습니다. 새로 요청해 주세요.")

    try:
        receive_ci(
            verification,
            phone_row,
            decrypt_match_token(verification.id, phone_row.match_token_enc),
        )
    except carrier.CarrierError as exc:
        current_app.logger.warning("MC-02 실패: verification_id=%s 사유=%s", verification.id, exc)
        terminate(verification, "P05")
        abort(503, description="통신사 응답이 없습니다. 잠시 후 다시 시작해 주세요.")

    advance_stage(verification, "ID_CARD")
    db.session.commit()
    current_app.logger.info("IA-24 CI 수령: verification_id=%s", verification.id)
    return jsonify(
        verification_id=str(verification.id),
        stage=verification.stage,
        passed=True,
        phone="PASSED",
        message="휴대폰 본인확인이 끝났습니다. 신분증을 제출해 주세요.",
    )
