"""관리자 인증: ID/PW + TOTP, 5회 실패 30분 잠금, 관리자별 허용 IP (W-06).

로그인은 두 단계다. 1단계에서 ID/PW를 확인하면 세션에 '대기 중' 표시만 남기고,
2단계에서 TOTP를 확인한 뒤에야 로그인 상태가 된다.
"""

from __future__ import annotations

import functools
import uuid

import bcrypt
import pyotp
from flask import abort, current_app, redirect, session, url_for
from flask_login import LoginManager, current_user, logout_user

from app.common import secrets as secret_store
from app.common.crypto import aad, decrypt_str
from app.common.timeutil import now_utc
from app.models import Admin, db

login_manager = LoginManager()
login_manager.login_view = "admin.login"
login_manager.session_protection = "strong"

SESSION_PENDING_ADMIN = "pending_admin_id"
SESSION_IMAGE_GRANT = "image_grant"


@login_manager.user_loader
def load_admin(user_id: str):
    try:
        return db.session.get(Admin, uuid.UUID(user_id))
    except (ValueError, TypeError):
        return None


@login_manager.unauthorized_handler
def _unauthorized():
    return redirect(url_for("admin.login"))


def is_locked(admin: Admin, now=None) -> bool:
    """잠금 상태인지 본다."""
    if admin.locked_until is None:
        return False
    return (now or now_utc()) < admin.locked_until


def check_password(admin: Admin, password: str) -> bool:
    """bcrypt 해시와 비교한다."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), admin.password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def totp_for(admin: Admin) -> pyotp.TOTP:
    """암호문으로 보관한 TOTP 시크릿을 풀어 검증기를 만든다."""
    secret = decrypt_str(
        secret_store.get_key("ekyc/admin-otp-key"),
        admin.otp_secret,
        aad("admins", "otp_secret", admin.id),
    )
    return pyotp.TOTP(secret)


def check_totp(admin: Admin, code: str) -> bool:
    """TOTP 검증(앞뒤 30초 허용)."""
    if not code or not code.strip().isdigit():
        return False
    return totp_for(admin).verify(code.strip(), valid_window=1)


def register_failure(admin: Admin) -> bool:
    """실패 횟수를 올리고, 상한에 닿으면 잠근다. 잠겼으면 True."""
    admin.failed_count += 1
    limit = current_app.config["ADMIN_MAX_FAILED"]
    locked = admin.failed_count >= limit
    if locked:
        admin.locked_until = now_utc() + current_app.config["ADMIN_LOCK_DURATION"]
        admin.failed_count = 0  # 잠금으로 대체한다
        current_app.logger.warning("관리자 계정 잠금: login_id=%s", admin.login_id)
    db.session.commit()
    return locked


def register_success(admin: Admin) -> None:
    """실패 횟수를 되돌리고 마지막 로그인 시각을 남긴다."""
    admin.failed_count = 0
    admin.locked_until = None
    admin.last_login_at = now_utc()
    db.session.commit()


def role_required(*roles: str):
    """역할 제한. auditor는 이력·접속기록 조회만 할 수 있다."""

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return _unauthorized()
            if current_user.role not in roles:
                current_app.logger.warning(
                    "권한 없는 접근: login_id=%s role=%s", current_user.login_id, current_user.role
                )
                abort(403, description="이 작업을 할 권한이 없다.")
            return view(*args, **kwargs)

        return wrapper

    return decorator


def clear_login_state() -> None:
    """로그인 중간 상태와 이미지 열람 승인을 모두 지운다."""
    session.pop(SESSION_PENDING_ADMIN, None)
    session.pop(SESSION_IMAGE_GRANT, None)
    if current_user.is_authenticated:
        logout_user()
