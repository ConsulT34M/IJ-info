"""위탁사 API 인증: API Key → 허용 IP → 타임스탬프 → 서명.

401 API Key·서명·타임스탬프 / 403 허용 IP 아님(D33).
"""

from __future__ import annotations

import functools

from flask import abort, current_app, g, request

from app.common import secrets as secret_store
from app.common.client_ip import client_ip
from app.common.hmac_auth import api_key_hash, ip_allowed, verify_signed_request
from app.models import Client, db


def require_client_auth(view):
    """서명이 확인된 위탁사만 통과시킨다. g.client에 위탁사를 담는다."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-Api-Key", "")
        if not api_key:
            abort(401, description="API Key가 없습니다.")

        client = db.session.scalars(
            db.select(Client).filter_by(api_key_hash=api_key_hash(api_key))
        ).one_or_none()
        if client is None or client.status != "ACTIVE":
            current_app.logger.warning("API Key 거부: ip=%s", client_ip())
            abort(401, description="API Key가 올바르지 않습니다.")

        if not ip_allowed(client_ip(), client.allowed_ips):
            current_app.logger.warning(
                "허용되지 않은 IP: client_id=%s ip=%s", client.id, client_ip()
            )
            abort(403, description="허용되지 않은 IP입니다.")

        error = verify_signed_request(
            secret_store.get_secret(client.hmac_secret_ref),
            request.headers.get("X-Timestamp"),
            request.get_data(cache=True),
            request.headers.get("X-Signature"),
            tolerance=current_app.config["API_TIMESTAMP_TOLERANCE"],
        )
        if error:
            current_app.logger.warning("서명 거부: client_id=%s 사유=%s", client.id, error)
            abort(401, description="서명 또는 타임스탬프가 올바르지 않습니다.")

        g.client = client
        return view(*args, **kwargs)

    return wrapper
