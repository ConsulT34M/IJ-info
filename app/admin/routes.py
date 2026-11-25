"""관리자 콘솔: 로그인 → TOTP → 이력 목록 → 상세, 접속기록, 이미지 열람, 권한 변경.

- 목록·상세는 성명·번호·주민번호를 마스킹하고 CI는 표시하지 않는다.
- 이미지 열람은 사유 입력이 필수이고 access_logs에 남는다(W-05).
- 시각은 모두 KST(+09:00)로 표시한다(D73).
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user

from app.admin.auth import (
    SESSION_IMAGE_GRANT,
    SESSION_PENDING_ADMIN,
    check_password,
    check_totp,
    clear_login_state,
    is_locked,
    register_failure,
    register_success,
    role_required,
)
from app.common import secrets as secret_store
from app.common.audit import log_access
from app.common.client_ip import client_ip
from app.common.crypto import DecryptError, aad, decrypt_str
from app.common.hmac_auth import ip_allowed
from app.common.log_mask import mask_name, mask_rrn
from app.common.storage import StorageError, get_storage
from app.common.timeutil import now_utc
from app.models import (
    AccessLog,
    Admin,
    FaceCheck,
    IdDocument,
    PhoneEvent,
    PhoneVerification,
    Verification,
    db,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")

PAGE_SIZE = 20
IMAGE_GRANT_SECONDS = 60  # 사유를 적고 열람 승인을 받은 뒤 이미지를 꺼낼 수 있는 시간
IMAGE_KINDS = ("id_card", "face")


@bp.before_request
def _enforce_admin_ip():
    """관리자별 허용 IP 밖에서는 로그인 상태를 끊는다(W-06)."""
    if current_user.is_authenticated and not ip_allowed(client_ip(), current_user.allowed_ips):
        current_app.logger.warning(
            "허용되지 않은 IP의 관리자 요청: login_id=%s ip=%s", current_user.login_id, client_ip()
        )
        clear_login_state()
        abort(403, description="허용되지 않은 접속 위치입니다.")


# --- 로그인 ---------------------------------------------------------------


@bp.route("/login", methods=["GET", "POST"])
def login():
    """1단계: ID/PW."""
    if current_user.is_authenticated:
        return redirect(url_for("admin.verification_list"))
    if request.method == "GET":
        return render_template("admin/login.html")

    login_id = (request.form.get("login_id") or "").strip()
    password = request.form.get("password") or ""
    admin = db.session.scalars(db.select(Admin).filter_by(login_id=login_id)).one_or_none()

    if admin is None:
        current_app.logger.warning("관리자 로그인 실패(없는 계정): ip=%s", client_ip())
        return render_template("admin/login.html", error=_LOGIN_FAILED), 401

    if is_locked(admin):
        return render_template("admin/login.html", error=_LOCKED), 401

    if not check_password(admin, password):
        locked = register_failure(admin)
        current_app.logger.warning(
            "관리자 로그인 실패: login_id=%s ip=%s", admin.login_id, client_ip()
        )
        return render_template("admin/login.html", error=_LOCKED if locked else _LOGIN_FAILED), 401

    session[SESSION_PENDING_ADMIN] = str(admin.id)
    session.permanent = True
    return redirect(url_for("admin.otp"))


@bp.route("/otp", methods=["GET", "POST"])
def otp():
    """2단계: TOTP."""
    pending = session.get(SESSION_PENDING_ADMIN)
    if not pending:
        return redirect(url_for("admin.login"))
    admin = db.session.get(Admin, uuid.UUID(pending))
    if admin is None:
        clear_login_state()
        return redirect(url_for("admin.login"))

    if request.method == "GET":
        return render_template("admin/otp.html", login_id=admin.login_id)

    if is_locked(admin):
        clear_login_state()
        return render_template("admin/login.html", error=_LOCKED), 401

    if not check_totp(admin, request.form.get("code") or ""):
        locked = register_failure(admin)
        current_app.logger.warning("관리자 OTP 실패: login_id=%s ip=%s", admin.login_id, client_ip())
        if locked:
            clear_login_state()
            return render_template("admin/login.html", error=_LOCKED), 401
        return render_template("admin/otp.html", login_id=admin.login_id, error=_OTP_FAILED), 401

    session.pop(SESSION_PENDING_ADMIN, None)
    login_user(admin)
    session.permanent = True
    register_success(admin)
    current_app.logger.info("관리자 로그인: login_id=%s ip=%s", admin.login_id, client_ip())
    return redirect(url_for("admin.verification_list"))


@bp.post("/logout")
@login_required
def logout():
    current_app.logger.info("관리자 로그아웃: login_id=%s", current_user.login_id)
    clear_login_state()
    return redirect(url_for("admin.login"))


# --- 이력 ------------------------------------------------------------------


@bp.get("/")
@login_required
def verification_list():
    """이력 목록. 조회 자체를 access_logs에 남긴다."""
    page = max(1, request.args.get("page", type=int, default=1))
    status_filter = request.args.get("status") or ""

    query = db.select(Verification).order_by(Verification.created_at.desc())
    if status_filter:
        query = query.where(Verification.status == status_filter)

    rows = db.session.scalars(query.limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)).all()
    total = db.session.scalar(
        db.select(db.func.count()).select_from(Verification)
        if not status_filter
        else db.select(db.func.count()).select_from(Verification).where(Verification.status == status_filter)
    )

    log_access(
        "admin",
        "HISTORY_VIEW",
        actor_id=current_user.login_id,
        ip=client_ip(),
    )
    db.session.commit()

    return render_template(
        "admin/list.html",
        items=[_summarize(row) for row in rows],
        page=page,
        page_size=PAGE_SIZE,
        total=total,
        status_filter=status_filter,
    )


@bp.get("/api/verifications")
@login_required
def verification_list_json():
    """목록 JSON API. 기본(양호)은 마스킹된 값만 돌려준다.

    VULN_W10을 켜면 주민번호 전체를 돌려주고 마스킹을 화면 JS에 맡긴다(9단계 실습).
    """
    rows = db.session.scalars(
        db.select(Verification).order_by(Verification.created_at.desc()).limit(PAGE_SIZE)
    ).all()
    expose_raw = bool(current_app.config.get("VULN_W10"))
    items = [_summarize(row, expose_raw_rrn=expose_raw) for row in rows]

    log_access("admin", "HISTORY_VIEW", actor_id=current_user.login_id, ip=client_ip())
    db.session.commit()
    return {"items": items, "count": len(items)}


@bp.get("/verifications/<uuid:verification_id>")
@login_required
def verification_detail(verification_id):
    """상세: 휴대폰 / 신분증 / 얼굴 탭."""
    verification = db.session.get(Verification, verification_id)
    if verification is None:
        abort(404, description="해당 건을 찾을 수 없습니다.")

    log_access(
        "admin",
        "HISTORY_VIEW",
        actor_id=current_user.login_id,
        target_id=str(verification_id),
        ip=client_ip(),
    )
    db.session.commit()

    phone = verification.phone
    document = verification.id_document
    events = db.session.scalars(
        db.select(PhoneEvent).filter_by(verification_id=verification_id).order_by(PhoneEvent.id)
    ).all()
    face_checks = db.session.scalars(
        db.select(FaceCheck).filter_by(verification_id=verification_id).order_by(FaceCheck.id)
    ).all()

    return render_template(
        "admin/detail.html",
        verification=verification,
        summary=_summarize(verification),
        phone=phone,
        phone_state=_phone_state(phone),
        document=document,
        document_view=_document_view(document),
        events=events,
        face_checks=face_checks,
        callbacks=verification.callbacks,
        can_view_image=current_user.role == "admin",
    )


# --- 이미지 열람 (사유 필수) -------------------------------------------------


@bp.post("/verifications/<uuid:verification_id>/image")
@role_required("admin")
def image_request(verification_id):
    """사유를 받고 열람을 승인한다. 승인은 짧은 시간만 유효하다."""
    verification = db.session.get(Verification, verification_id)
    if verification is None:
        abort(404)

    kind = request.form.get("kind") or ""
    reason = (request.form.get("reason") or "").strip()
    if kind not in IMAGE_KINDS:
        abort(400, description="열람 대상이 올바르지 않습니다.")
    if len(reason) < 5:
        return redirect(url_for("admin.verification_detail", verification_id=verification_id, error="reason"))

    key = _image_key(verification, kind)
    if key is None:
        return render_template("admin/image.html", purged=True, kind=kind, verification=verification)

    log_access(
        "admin",
        "IMAGE_VIEW",
        actor_id=current_user.login_id,
        target_id=f"{verification_id}:{kind}",
        reason=reason,
        ip=client_ip(),
    )
    db.session.commit()

    session[SESSION_IMAGE_GRANT] = {
        "verification_id": str(verification_id),
        "kind": kind,
        "until": (now_utc() + timedelta(seconds=IMAGE_GRANT_SECONDS)).isoformat(),
    }
    current_app.logger.info(
        "이미지 열람 승인: login_id=%s target=%s:%s", current_user.login_id, verification_id, kind
    )
    return render_template(
        "admin/image.html",
        purged=False,
        kind=kind,
        verification=verification,
        reason=reason,
        valid_seconds=IMAGE_GRANT_SECONDS,
    )


@bp.get("/verifications/<uuid:verification_id>/image/<kind>/raw")
@role_required("admin")
def image_raw(verification_id, kind: str):
    """승인된 열람만 이미지를 내려준다. 웹 루트 밖 파일을 관리자 전용 라우트로만 지난다(W-05)."""
    grant = session.get(SESSION_IMAGE_GRANT) or {}
    if (
        grant.get("verification_id") != str(verification_id)
        or grant.get("kind") != kind
        or kind not in IMAGE_KINDS
    ):
        abort(403, description="열람 사유를 먼저 입력해 주세요.")
    if now_utc().isoformat() > grant.get("until", ""):
        session.pop(SESSION_IMAGE_GRANT, None)
        abort(410, description="열람 유효시간이 지났습니다. 사유를 다시 입력해 주세요.")

    verification = db.session.get(Verification, verification_id)
    if verification is None:
        abort(404)
    key = _image_key(verification, kind)
    if key is None:
        abort(404, description="이미지가 파기되었습니다.")

    try:
        data = get_storage().load(key)
    except StorageError:
        abort(404, description="이미지가 파기되었습니다.")

    media_type = "image/png" if key.endswith(".png") else "image/jpeg"
    return Response(data, mimetype=media_type, headers={"Cache-Control": "no-store"})


# --- 접속기록 --------------------------------------------------------------


@bp.get("/inquiries")
@login_required
def inquiry_list():
    """홈페이지 문의 목록(admin·auditor 모두)."""
    from app.models import SiteInquiry

    page = max(1, request.args.get("page", type=int, default=1))
    rows = db.session.scalars(
        db.select(SiteInquiry)
        .order_by(SiteInquiry.id.desc())
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    ).all()
    total = db.session.scalar(db.select(db.func.count()).select_from(SiteInquiry)) or 0
    return render_template(
        "admin/inquiries.html", rows=rows, page=page, total=total, page_size=PAGE_SIZE
    )


@bp.get("/inquiries/<int:inquiry_id>")
@login_required
def inquiry_detail(inquiry_id: int):
    """문의 상세.

    양호: 본문을 Jinja autoescape로 그대로 출력한다(W-02).
    VULN_W02를 켜면 화면에서 `| safe`로 내보내 저장형 XSS가 성립한다(D90).
    """
    from app.models import SiteInquiry

    row = db.session.get(SiteInquiry, inquiry_id)
    if row is None:
        abort(404, description="해당 문의를 찾을 수 없습니다.")
    return render_template(
        "admin/inquiry_detail.html",
        row=row,
        render_raw=bool(current_app.config.get("VULN_W02")),
    )


@bp.get("/access-logs")
@login_required
def access_logs():
    """접속·열람 기록 조회(admin·auditor 모두)."""
    page = max(1, request.args.get("page", type=int, default=1))
    action_filter = request.args.get("action") or ""

    query = db.select(AccessLog).order_by(AccessLog.id.desc())
    if action_filter:
        query = query.where(AccessLog.action == action_filter)
    rows = db.session.scalars(query.limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)).all()

    from app.models import ACCESS_ACTIONS

    return render_template(
        "admin/access_logs.html",
        rows=rows,
        page=page,
        action_filter=action_filter,
        actions=ACCESS_ACTIONS,
    )


# --- 권한 변경 -------------------------------------------------------------


@bp.get("/admins")
@role_required("admin")
def admin_list():
    rows = db.session.scalars(db.select(Admin).order_by(Admin.login_id)).all()
    return render_template("admin/admins.html", admins=rows)


@bp.post("/admins/<uuid:admin_id>/role")
@role_required("admin")
def change_role(admin_id):
    """역할 변경. ROLE_CHANGE로 남긴다."""
    target = db.session.get(Admin, admin_id)
    if target is None:
        abort(404)
    new_role = request.form.get("role") or ""
    if new_role not in ("admin", "auditor"):
        abort(400, description="역할 값이 올바르지 않습니다.")
    if target.id == current_user.id and new_role != "admin":
        abort(400, description="본인의 권한은 낮출 수 없습니다.")

    previous = target.role
    target.role = new_role
    log_access(
        "admin",
        "ROLE_CHANGE",
        actor_id=current_user.login_id,
        target_id=target.login_id,
        reason=f"{previous} → {new_role}",
        ip=client_ip(),
    )
    db.session.commit()
    current_app.logger.info(
        "권한 변경: by=%s target=%s %s→%s", current_user.login_id, target.login_id, previous, new_role
    )
    return redirect(url_for("admin.admin_list"))


# --- 표시용 변환 ------------------------------------------------------------

_LOGIN_FAILED = "아이디 또는 비밀번호가 올바르지 않습니다."
_OTP_FAILED = "인증 앱의 6자리 코드가 올바르지 않습니다."
_LOCKED = "로그인 실패가 반복되어 계정이 잠겼습니다. 30분 후 다시 시도해 주세요."


def _image_key(verification: Verification, kind: str) -> str | None:
    if kind == "id_card":
        document = verification.id_document
        return document.s3_key if document else None
    check = next((row for row in verification.face_checks if row.s3_key), None)
    return check.s3_key if check else None


def _decrypt_rrn(document: IdDocument) -> str | None:
    if document is None or document.rrn_enc is None:
        return None
    try:
        return decrypt_str(
            secret_store.get_key("ekyc/rrn-key"),
            document.rrn_enc,
            aad("id_documents", "rrn_enc", document.verification_id),
        )
    except DecryptError:
        current_app.logger.error("주민번호 복호화 실패: verification_id=%s", document.verification_id)
        return None


def _summarize(verification: Verification, *, expose_raw_rrn: bool = False) -> dict:
    """목록·JSON용 요약. 기본은 전부 마스킹하고 CI는 넣지 않는다."""
    document = verification.id_document
    phone = verification.phone
    identity_event = next(
        (row for row in verification.events if row.event_kind == "IDENTITY_MATCH"), None
    )
    rrn = _decrypt_rrn(document)

    summary = {
        "verification_id": str(verification.id),
        "client_name": verification.client.name,
        "client_user_ref": verification.client_user_ref,
        "stage": verification.stage,
        "status": verification.status,
        "reason_code": verification.reason_code,
        "last_error_code": verification.last_error_code,
        "created_at": verification.created_at,
        "completed_at": verification.completed_at,
        "name_mask": mask_name(document.name) if document else (identity_event.name_mask if identity_event else ""),
        "phone_mask": identity_event.phone_mask if identity_event else "",
        "rrn_mask": mask_rrn(rrn) if rrn else "",
        "ci_mismatch": document.ci_matched is False if document else False,
        "ci_stored": bool(phone and phone.ci),
        "ci_purged_at": phone.ci_purged_at if phone else None,
    }
    if expose_raw_rrn:
        # VULN_W10: 마스킹을 화면 JS에 맡기고 원본을 그대로 내보낸다
        summary["rrn"] = rrn
    return summary


def _phone_state(phone: PhoneVerification | None) -> dict:
    if phone is None:
        return {"status": "NOT_STARTED", "ci_label": "없음"}
    if phone.ci_purged_at is not None:
        ci_label = "파기됨"
    elif phone.ci:
        ci_label = "보관 중(비표시)"
    else:
        ci_label = "없음"
    return {"status": phone.status, "ci_label": ci_label}


def _document_view(document: IdDocument | None) -> dict:
    if document is None:
        return {"present": False}
    rrn = _decrypt_rrn(document)
    return {
        "present": True,
        "name_mask": mask_name(document.name),
        "rrn_mask": mask_rrn(rrn) if rrn else "-",
        "birth_date": document.birth_date,
        "issue_date": document.issue_date,
        "ci_matched": document.ci_matched,
        "mois_matched": document.mois_matched,
        "image_label": "파기됨" if document.s3_key is None else "보관 중",
    }
