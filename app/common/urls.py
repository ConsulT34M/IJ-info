"""URL 검사. 오픈 리다이렉트(D5)와 평문 전송(D29)을 막는다."""

from __future__ import annotations

from urllib.parse import ParseResult, urlparse

from flask import current_app


def allowed_schemes(env: str | None = None) -> tuple[str, ...]:
    """D29: production은 https만. dev는 로컬 http도 허용한다."""
    name = env if env is not None else current_app.config.get("EKYC_ENV", "dev")
    return ("https",) if str(name).lower() == "production" else ("http", "https")


def parse_absolute_url(value: str | None, env: str | None = None) -> ParseResult | None:
    """허용 스킴의 절대 URL이면 파싱 결과를, 아니면 None."""
    if not value or not isinstance(value, str) or len(value) > 500:
        return None
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() not in allowed_schemes(env):
        return None
    if not parsed.netloc or parsed.fragment:
        return None
    return parsed


def origin_of(value: str) -> tuple[str, str] | None:
    """(스킴, 호스트:포트) 쌍. 비교용이라 소문자로 맞춘다."""
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    return (parsed.scheme.lower(), parsed.netloc.lower())


def same_origin(left: str, right: str) -> bool:
    """D5: return_url은 해당 client의 callback_url과 같은 origin만 허용한다."""
    left_origin = origin_of(left)
    right_origin = origin_of(right)
    return bool(left_origin) and left_origin == right_origin
