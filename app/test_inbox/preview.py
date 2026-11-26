"""로컬 시연에서만 쓰는 짧은 수명 인증번호 화면 토큰.

이 토큰을 가진 브라우저는 전화기 소유를 증명하지 않고 번호를 볼 수 있다.
운영 환경에서는 발급하거나 받지 않는다.
"""

from __future__ import annotations

from flask import current_app
from itsdangerous import BadSignature, URLSafeTimedSerializer


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.secret_key, salt="local-test-inbox-preview-v1")


def issue_preview_token(verification_id, issue_no: int) -> str | None:
    if current_app.config["EKYC_ENV"] == "production":
        return None
    return _serializer().dumps({"verification_id": str(verification_id), "issue_no": issue_no})


def read_preview_token(token: str) -> tuple[str, int] | None:
    if current_app.config["EKYC_ENV"] == "production":
        return None
    try:
        data = _serializer().loads(token, max_age=180)
    except BadSignature:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("verification_id"), str):
        return None
    if type(data.get("issue_no")) is not int:
        return None
    return data["verification_id"], data["issue_no"]
