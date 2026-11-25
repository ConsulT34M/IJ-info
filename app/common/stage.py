"""인증창 stage 검사와 서버 세션 처리.

모든 인증창 라우트는 @require_stage(...)로 서버에서 stage를 확인한다. 위반 시 403.
세션에는 verification_id·entry_nonce·성명·휴대폰번호만 담는다. 쿠키에는 세션 ID만 나간다.
"""

from __future__ import annotations

import functools
import uuid

from flask import abort, current_app, g, redirect, session, url_for

from app.common.timeutil import is_expired
from app.models import Verification, db

SESSION_VERIFICATION_ID = "verification_id"
SESSION_ENTRY_NONCE = "entry_nonce"
SESSION_NAME = "name"
SESSION_PHONE_NUMBER = "phone_number"
# 결과 화면용. 개인정보는 넣지 않는다(판정 결과와 돌아갈 주소만)
SESSION_RESULT = "result"

# stage → 그 단계의 화면. 구현 단계마다 라우트가 생긴다.
STAGE_ENDPOINTS = {
    "CONSENT": "verify.consent_page",
    "PHONE": "verify.phone_page",
    "ID_CARD": "verify.id_card_page",
    "ID_CONFIRM": "verify.id_confirm_page",
    "FACE": "verify.face_page",
    "DONE": "verify.result_page",
}


def _drop_cached_csrf_token() -> None:
    """요청 컨텍스트에 캐시된 CSRF 토큰을 버린다.

    세션을 비우면 CSRF 원본값도 사라지므로, g에 남은 캐시를 함께 버려야 다음 화면에서
    새 토큰을 만들어 세션에 다시 심는다.
    """
    g.pop(current_app.config.get("WTF_CSRF_FIELD_NAME", "csrf_token"), None)


def start_session(verification: Verification) -> None:
    """인증창 진입 시 서버 세션을 새로 만든다(세션 고정 방지)."""
    session.clear()
    _drop_cached_csrf_token()
    regenerate = getattr(current_app.session_interface, "regenerate", None)
    if callable(regenerate):
        regenerate(session)
    session.permanent = True
    session[SESSION_VERIFICATION_ID] = str(verification.id)
    session[SESSION_ENTRY_NONCE] = verification.entry_nonce


def end_session() -> None:
    """인증창 세션을 비운다."""
    session.clear()
    _drop_cached_csrf_token()


def session_verification_id() -> uuid.UUID | None:
    raw = session.get(SESSION_VERIFICATION_ID)
    try:
        return uuid.UUID(str(raw)) if raw else None
    except ValueError:
        return None


def load_session_verification() -> Verification:
    """세션의 인증 건을 꺼낸다. 문제가 있으면 바로 중단한다.

    403 세션 없음 / 404 없는 건 / 410 다른 탭에서 무효화됨·만료 / 409 종결된 건
    """
    verification_id = session_verification_id()
    if verification_id is None:
        abort(403)

    verification = db.session.get(Verification, verification_id)
    if verification is None:
        end_session()
        abort(404)

    # D7: 토큰을 재발급하면 entry_nonce가 바뀌어 이전 탭은 못 쓴다
    if not verification.entry_nonce or session.get(SESSION_ENTRY_NONCE) != verification.entry_nonce:
        end_session()
        abort(410)

    if verification.is_finished:
        abort(409)

    if is_expired(verification.expires_at):
        from app.verify.termination import terminate

        terminate(verification, "P03")
        end_session()
        abort(410)

    return verification


def require_stage(*allowed: str, vuln_flag: str | None = None):
    """현재 stage가 allowed에 없으면 403.

    vuln_flag가 켜져 있으면 stage 검사만 건너뛴다(14장 VULN_W09 실습용).
    """

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            verification = load_session_verification()
            skip_check = bool(vuln_flag) and bool(current_app.config.get(vuln_flag))
            if not skip_check and verification.stage not in allowed:
                current_app.logger.info(
                    "stage 위반: verification_id=%s stage=%s allowed=%s",
                    verification.id,
                    verification.stage,
                    ",".join(allowed),
                )
                abort(403)
            g.verification = verification
            return view(*args, **kwargs)

        return wrapper

    return decorator


def advance_stage(verification: Verification, stage: str) -> None:
    """stage를 다음 단계로 옮긴다."""
    if stage not in STAGE_ENDPOINTS:
        raise ValueError(f"없는 stage: {stage}")
    verification.stage = stage


def stage_redirect(verification: Verification):
    """현재 stage의 화면으로 보낸다. URL에는 토큰·개인정보를 넣지 않는다."""
    endpoint = STAGE_ENDPOINTS.get(verification.stage)
    if not endpoint or endpoint not in current_app.view_functions:
        current_app.logger.error("아직 구현되지 않은 단계: %s", verification.stage)
        abort(503)
    return redirect(url_for(endpoint))
