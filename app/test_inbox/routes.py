"""IA-05 테스트 문자 수신함 + 기기 등록 (실습 전용, 진단 범위 제외).

실제 문자를 보낼 수 없으니 여기서 인증번호를 꺼내 본다. D3에 따라
TEST_INBOX_ALLOWED_IPS에 있는 IP만 접근할 수 있다.

수신함 키는 `tools/pass_app.py`(모의 PASS 앱)가 기기 등록으로 발급받는다(D85).
people.json의 값을 그대로 쓰는 것도 아직 된다.
"""

from __future__ import annotations

from datetime import date
from secrets import token_urlsafe

from flask import Blueprint, abort, current_app, jsonify, render_template, request

from app.common import carrier
from app.common.client_ip import client_ip
from app.common.crypto import sha256_hex
from app.common.hmac_auth import ip_allowed
from app.common.phone import decrypt_from_inbox, normalize_phone, phone_key, validate_name
from app.common.timeutil import kst_isoformat, now_utc
from app.models import PhoneOtp, TestPhone, db

bp = Blueprint("test_inbox", __name__, url_prefix="/test-inbox")


@bp.before_request
def _only_allowed_ips():
    """허용 IP가 아니면 화면 자체를 열지 않는다."""
    if not ip_allowed(client_ip(), current_app.config["TEST_INBOX_ALLOWED_IPS"]):
        current_app.logger.warning("테스트 수신함 접근 거부: ip=%s", client_ip())
        abort(403)


@bp.get("/")
def inbox_page():
    """수신함 키 입력 화면."""
    return render_template("test_inbox/inbox.html")


def _wants_json() -> bool:
    """모의 PASS 앱은 JSON으로 받고, 브라우저는 화면으로 받는다."""
    accept = request.accept_mimetypes
    return accept["application/json"] > accept["text/html"]


def _inbox_error(message: str, status: int, phone_mask: str | None = None):
    """수신함 오류를 요청한 형식으로 돌려준다."""
    if _wants_json():
        return jsonify(error=message, phone_mask=phone_mask), status
    return render_template("test_inbox/inbox.html", error=message, phone_mask=phone_mask), status


@bp.post("/latest")
def latest():
    """수신함 키로 가장 최근의 유효한 인증번호를 꺼낸다."""
    inbox_key = (request.form.get("inbox_key") or "").strip()
    if not inbox_key:
        return _inbox_error("수신함 키를 입력해 주세요.", 400)

    phone = db.session.scalars(
        db.select(TestPhone).filter_by(inbox_key_hash=sha256_hex(inbox_key))
    ).one_or_none()
    if phone is None:
        return _inbox_error("수신함을 찾을 수 없습니다.", 404)

    otp = db.session.scalars(
        db.select(PhoneOtp)
        .where(
            PhoneOtp.phone_key == phone.phone_key,
            PhoneOtp.inbox_ciphertext.is_not(None),
            PhoneOtp.code_expires_at > now_utc(),
        )
        .order_by(PhoneOtp.issued_at.desc())
    ).first()
    if otp is None:
        return _inbox_error(
            "유효한 인증번호가 없습니다. 인증 화면에서 먼저 발송해 주세요.", 404, phone.phone_mask
        )

    code = decrypt_from_inbox(otp.verification_id, otp.inbox_ciphertext)
    expires_at = kst_isoformat(otp.code_expires_at)
    if _wants_json():
        return jsonify(
            phone_mask=phone.phone_mask,
            code=code,
            code_expires_at=expires_at,
            issue_no=otp.issue_no,
        )
    return render_template(
        "test_inbox/inbox.html",
        phone_mask=phone.phone_mask,
        code=code,
        code_expires_at=expires_at,
        issue_no=otp.issue_no,
    )


@bp.post("/devices")
def register_device():
    """모의 PASS 앱의 기기 등록. 통신사 명의 확인(MC-03)을 통과하면 수신함 키를 준다.

    실제로는 본인 명의 휴대폰을 들고 있다는 것이 수신함의 열쇠다. 실습에서는
    people.json의 inbox_key를 복붙해 왔는데, 그 대신 통신사에 명의를 확인받고
    키를 발급받는 경로를 둔다(D85).

    새로 등록하면 그 번호의 이전 키는 바로 못 쓴다(기기 하나만 유효).
    """
    phone = normalize_phone(request.form.get("phone_number"))
    name = validate_name(request.form.get("name"))
    birth_date = (request.form.get("birth_date") or "").strip()

    if phone is None:
        return jsonify(error="휴대폰번호 형식이 올바르지 않습니다."), 400
    if name is None:
        return jsonify(error="성명을 입력해 주세요."), 400
    if not _looks_like_a_date(birth_date):
        return jsonify(error="생년월일은 YYYY-MM-DD 형식으로 입력해 주세요."), 400

    row = db.session.get(TestPhone, phone_key(phone))
    if row is None:
        # 수신함이 없는 번호다. 통신사를 부르기 전에 끊어 호출을 아낀다.
        return jsonify(error="등록할 수 없습니다. 번호와 명의를 확인해 주세요."), 400

    try:
        result = carrier.register_device(name, phone, birth_date)
    except carrier.CarrierError as exc:
        current_app.logger.warning("MC-03 실패: %s", exc)
        return jsonify(error="통신사 응답이 없습니다. 통신사 앱이 실행 중인지 확인해 주세요."), 503

    if not result.matched:
        # W-14와 같은 기준: 어느 항목이 틀렸는지 알려주지 않는다
        current_app.logger.info("기기 등록 거부: reason=%s", result.reason)
        return jsonify(error="등록할 수 없습니다. 번호와 명의를 확인해 주세요."), 403

    inbox_key = token_urlsafe(24)
    row.inbox_key_hash = sha256_hex(inbox_key)
    db.session.commit()
    current_app.logger.info("기기 등록: phone_mask=%s", row.phone_mask)
    return jsonify(inbox_key=inbox_key, phone_mask=row.phone_mask), 200


def _looks_like_a_date(value: str) -> bool:
    """YYYY-MM-DD 형태인지만 본다. 실제 대조는 통신사가 한다."""
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return len(value) == 10
