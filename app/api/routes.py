"""IA-01 인증 요청, IA-12 결과 조회."""

from __future__ import annotations

import time
from datetime import timedelta
from secrets import token_urlsafe

from flask import Blueprint, abort, current_app, g, jsonify, request

from app.api.auth import require_client_auth
from app.api.webhook import build_result_payload, mark_ci_delivered
from app.common.audit import log_access
from app.common.client_ip import client_ip
from app.common.crypto import sha256_hex
from app.common.timeutil import is_expired, kst_isoformat, now_utc
from app.common.urls import parse_absolute_url, same_origin
from app.models import Verification, db

bp = Blueprint("api", __name__, url_prefix="/api/v1")

MAX_CLIENT_USER_REF = 100


def issue_entry_token(verification: Verification) -> str:
    """인증창 토큰을 발급한다(10분·1회용).

    D36: 만료 시각을 토큰 앞에 담고 토큰 전체의 sha256만 저장한다. 값을 고치면 해시가 달라져
    조회되지 않으므로 별도 컬럼 없이 10분 제한이 성립한다.
    """
    ttl = int(current_app.config["ENTRY_TOKEN_TTL"].total_seconds())
    token = f"{int(time.time()) + ttl}.{token_urlsafe(32)}"
    verification.token_hash = sha256_hex(token)
    verification.token_used_at = None
    # D7: 토큰을 새로 발급하면 기존 인증창 세션도 무효가 된다
    verification.entry_nonce = token_urlsafe(24)
    return token


def auth_url_for(token: str) -> str:
    base = current_app.config["PUBLIC_BASE_URL"].rstrip("/")
    return f"{base}/verify/start/{token}"


@bp.post("/verifications")
@require_client_auth
def create_verification():
    """IA-01. 거래소가 인증을 1회 요청한다.

    201 새 건 / 200 진행 중인 기존 건(인증창 토큰만 재발급, D12)
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON 본문이 필요합니다.")

    client_user_ref = payload.get("client_user_ref")
    if not isinstance(client_user_ref, str) or not client_user_ref.strip():
        abort(400, description="client_user_ref가 필요합니다.")
    client_user_ref = client_user_ref.strip()
    if len(client_user_ref) > MAX_CLIENT_USER_REF:
        abort(400, description="client_user_ref가 너무 깁니다.")

    return_url = payload.get("return_url")
    if parse_absolute_url(return_url) is None:
        abort(400, description="return_url이 허용된 절대 주소가 아닙니다.")
    # D5: 오픈 리다이렉트 방지. callback_url과 같은 origin만 받는다
    if not same_origin(return_url, g.client.callback_url):
        abort(400, description="return_url은 callback_url과 같은 origin이어야 합니다.")

    existing = db.session.scalars(
        db.select(Verification)
        .filter_by(client_id=g.client.id, client_user_ref=client_user_ref, status="PENDING")
        .order_by(Verification.created_at.desc())
    ).first()

    if existing is not None and is_expired(existing.expires_at):
        from app.verify.termination import terminate

        terminate(existing, "P03")
        existing = None

    if existing is not None:
        token = issue_entry_token(existing)
        existing.return_url = return_url
        log_access(
            "client",
            "REQUEST_RECEIVED",
            actor_id=str(g.client.id),
            target_id=str(existing.id),
            ip=client_ip(),
        )
        db.session.commit()
        current_app.logger.info(
            "IA-01 기존 건 반환: verification_id=%s client_id=%s", existing.id, g.client.id
        )
        return jsonify(_response_body(existing, token)), 200

    created = now_utc()
    verification = Verification(
        client_id=g.client.id,
        client_user_ref=client_user_ref,
        return_url=return_url,
        created_at=created,
        expires_at=created + current_app.config["VERIFICATION_TTL"],
    )
    token = issue_entry_token(verification)
    db.session.add(verification)
    db.session.flush()
    log_access(
        "client",
        "REQUEST_RECEIVED",
        actor_id=str(g.client.id),
        target_id=str(verification.id),
        ip=client_ip(),
    )
    db.session.commit()
    current_app.logger.info(
        "IA-01 새 건: verification_id=%s client_id=%s", verification.id, g.client.id
    )
    return jsonify(_response_body(verification, token)), 201


@bp.get("/verifications/<uuid:verification_id>")
@require_client_auth
def read_verification(verification_id):
    """IA-12. 웹훅이 유실됐을 때 결과를 조회한다(주민번호·이미지는 넣지 않는다).

    양호 기본값: 다른 위탁사 건은 404. VULN_W08을 켜면 소유 확인을 하지 않는다.
    """
    verification = db.session.get(Verification, verification_id)
    if verification is None:
        abort(404, description="해당 건을 찾을 수 없습니다.")

    if not current_app.config.get("VULN_W08") and verification.client_id != g.client.id:
        current_app.logger.warning(
            "다른 위탁사 건 조회 시도: client_id=%s verification_id=%s",
            g.client.id,
            verification_id,
        )
        abort(404, description="해당 건을 찾을 수 없습니다.")

    payload = build_result_payload(verification)
    phone = verification.phone
    payload["ci_purged_at"] = kst_isoformat(phone.ci_purged_at) if phone is not None else None

    # 웹훅이 유실된 경우 첫 조회 시점을 CI 전달 시점으로 기록한다
    if verification.status == "SUCCEEDED":
        mark_ci_delivered(verification)

    log_access(
        "client",
        "RESULT_QUERIED",
        actor_id=str(g.client.id),
        target_id=str(verification.id),
        ip=client_ip(),
    )
    db.session.commit()
    return jsonify(payload), 200


def _response_body(verification: Verification, token: str) -> dict:
    return {
        "verification_id": str(verification.id),
        "auth_url": auth_url_for(token),
        "expires_at": kst_isoformat(verification.expires_at),
    }
