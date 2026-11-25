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
from app.common.phone import validate_name
from app.common.rrn import validate_issue_date, validate_rrn
from app.common.storage import StorageError, get_storage
from app.common.timeutil import is_expired, now_utc
from app.common.upload import validate_image_upload
from app.mock_mois import verify as mois_verify
from app.models import Consent, FaceCheck, IdDocument, Verification, db
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

    ci = payload.get("ci")
    if not isinstance(ci, str) or len(ci) != CI_LENGTH:
        abort(400, description=f"ci가 필요합니다({CI_LENGTH}자). 휴대폰 본인확인에서 받은 값입니다.")

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

    # X-01: 위탁사가 보낸 CI와 제출된 주민번호로 계산한 CI를 대조한다(W-13)
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
