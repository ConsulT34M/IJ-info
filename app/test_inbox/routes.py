"""IA-05 테스트 문자 수신함 (실습 전용, 진단 범위 제외).

실제 문자를 보낼 수 없으니 여기서 인증번호를 꺼내 본다. D3에 따라
TEST_INBOX_ALLOWED_IPS에 있는 IP만 접근할 수 있다.
"""

from __future__ import annotations

from flask import Blueprint, abort, current_app, render_template, request

from app.common.client_ip import client_ip
from app.common.crypto import sha256_hex
from app.common.hmac_auth import ip_allowed
from app.common.phone import decrypt_from_inbox
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


@bp.post("/latest")
def latest():
    """수신함 키로 가장 최근의 유효한 인증번호를 꺼낸다."""
    inbox_key = (request.form.get("inbox_key") or "").strip()
    if not inbox_key:
        return render_template("test_inbox/inbox.html", error="수신함 키를 입력한다."), 400

    phone = db.session.scalars(
        db.select(TestPhone).filter_by(inbox_key_hash=sha256_hex(inbox_key))
    ).one_or_none()
    if phone is None:
        return render_template("test_inbox/inbox.html", error="수신함을 찾을 수 없다."), 404

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
        return (
            render_template(
                "test_inbox/inbox.html",
                phone_mask=phone.phone_mask,
                error="유효한 인증번호가 없다. 인증창에서 먼저 발송한다.",
            ),
            404,
        )

    return render_template(
        "test_inbox/inbox.html",
        phone_mask=phone.phone_mask,
        code=decrypt_from_inbox(otp.verification_id, otp.inbox_ciphertext),
        code_expires_at=kst_isoformat(otp.code_expires_at),
        issue_no=otp.issue_no,
    )
