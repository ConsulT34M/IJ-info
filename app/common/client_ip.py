"""접속 IP는 이 헬퍼 하나로만 읽는다.

TRUST_PROXY=True일 때만 X-Real-IP(Apache가 덮어쓴 값)를 믿는다. 아니면 remote_addr.
X-Forwarded-For는 클라이언트가 자유롭게 넣을 수 있어 쓰지 않는다.
"""

from __future__ import annotations

from flask import current_app, request


def client_ip() -> str:
    """현재 요청의 접속 IP."""
    if current_app.config.get("TRUST_PROXY"):
        forwarded = request.headers.get("X-Real-IP")
        if forwarded and forwarded.strip():
            return forwarded.strip()
    return request.remote_addr or ""
