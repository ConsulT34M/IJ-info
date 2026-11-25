"""설정값과 취약 플래그.

9장의 설정값은 전부 여기 모은다. 취약 플래그(VULN_*)는 기본 전부 False다.
시크릿에 의존하는 값(SECRET_KEY, DB DSN)은 init_app_config()에서 채운다.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from cachelib.file import FileSystemCache

from app.common import secrets as secret_store

# 14장 취약 플래그. 진단 증적의 기준이라 목록을 코드에 고정해 둔다.
VULN_FLAGS = ("VULN_W08", "VULN_W09", "VULN_W10", "VULN_W14", "VULN_W17", "VULN_C10")


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        return int(raw) if raw not in (None, "") else default
    except ValueError:
        return default


def env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


class Config:
    """환경과 무관한 기본 설정."""

    # --- 9장 설정값 ---
    ENTRY_TOKEN_TTL = timedelta(minutes=10)       # 인증창 토큰 10분·1회용
    VERIFICATION_TTL = timedelta(minutes=20)      # 건 전체 20분
    OTP_TTL = timedelta(minutes=3)                # 인증번호 3분
    OTP_RESEND_INTERVAL = timedelta(seconds=60)   # 재발송 60초(이내면 429)
    OTP_MAX_ISSUES = 5                            # 건당 발송 5회까지(초과는 429, 종결은 안 함)
    MATCH_MAX_ATTEMPTS = 3                        # 명의 대조 3회
    OTP_MAX_ATTEMPTS = 3                          # 인증번호 3회
    FACE_MAX_ATTEMPTS = 3                         # 얼굴 단계(E01~E05) 시도 합산 3회
    FACE_SIMILARITY_THRESHOLD = 90                # 유사도 90 이상이면 일치
    UPLOAD_MAX_BYTES = 5 * 1024 * 1024            # 업로드 5MB
    UPLOAD_ALLOWED_EXTENSIONS = ("jpg", "jpeg", "png")
    CI_RETENTION_AFTER_DELIVERY = timedelta(days=7)    # 첫 수령 후 7일
    CI_RETENTION_WITHOUT_DELIVERY = timedelta(days=30)  # 미수령 시 판정 후 30일
    ADMIN_MAX_FAILED = 5                          # 관리자 5회 실패
    ADMIN_LOCK_DURATION = timedelta(minutes=30)   # 30분 잠금
    ADMIN_SESSION_TIMEOUT = timedelta(minutes=30) # 관리자 세션 30분
    API_TIMESTAMP_TOLERANCE = 300                 # X-Timestamp ±5분
    WEBHOOK_TIMEOUT = 3                           # 웹훅 타임아웃 3초

    # 약관 버전 (동의 기록에 남긴다)
    CONSENT_VERSIONS = {
        "collect": "v1.0",
        "uid": "v1.0",
        "carrier_terms": "v1.0",
        "biometric": "v1.0",
    }

    # --- Flask ---
    MAX_CONTENT_LENGTH = UPLOAD_MAX_BYTES + 64 * 1024  # 폼 필드 여유분
    JSON_SORT_KEYS = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    WTF_CSRF_TIME_LIMIT = None  # 세션 수명과 같이 간다

    # --- 세션 쿠키 (W-07) ---
    SESSION_COOKIE_NAME = "ekyc_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_TYPE = "cachelib"  # 서버 사이드 세션. 쿠키에는 세션 ID만 담긴다
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = ADMIN_SESSION_TIMEOUT
    SESSION_KEY_PREFIX = "ekyc:"

    # --- Content-Security-Policy (W-02) ---
    CONTENT_SECURITY_POLICY = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'"
    )


def init_app_config(app, overrides: dict | None = None) -> None:
    """app.config를 채운다. 시크릿·환경변수에 의존하는 값은 여기서 읽는다."""
    app.config.from_object(Config)

    env_name = os.environ.get("EKYC_ENV", "dev").strip().lower()
    is_dev = env_name != "production"

    app.config.update(
        EKYC_ENV=env_name,
        TRUST_PROXY=env_bool("TRUST_PROXY", False),
        TEST_INBOX_ALLOWED_IPS=env_list("TEST_INBOX_ALLOWED_IPS", ["127.0.0.1", "::1"]),
        PUBLIC_BASE_URL=os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:8000"),
        CARRIER_BASE_URL=os.environ.get("CARRIER_BASE_URL", "https://localhost:8443"),
        CARRIER_CA_BUNDLE=os.environ.get("CARRIER_CA_BUNDLE", "carrier/certs/carrier.crt"),
        # D22: 로컬 http 개발에서만 Secure를 끈다. production은 반드시 True.
        SESSION_COOKIE_SECURE=env_bool("SESSION_COOKIE_SECURE", not is_dev),
        WTF_CSRF_SSL_STRICT=not is_dev,
        UPLOAD_DIR=Path(app.instance_path) / "uploads",
    )

    for flag in VULN_FLAGS:
        app.config[flag] = env_bool(flag, False)

    app.config["SECRET_KEY"] = secret_store.get_secret("ekyc/flask-secret")
    app.config["SQLALCHEMY_DATABASE_URI"] = secret_store.get_secret("ekyc/db")
    app.config["SESSION_CACHELIB"] = FileSystemCache(
        cache_dir=str(Path(app.instance_path) / "sessions"),
        threshold=1000,
        mode=0o600,
    )

    if overrides:
        app.config.update(overrides)


def enabled_vuln_flags(app) -> list[str]:
    """켜져 있는 취약 플래그 목록. 기동 로그와 관리자 화면에 쓴다."""
    return [flag for flag in VULN_FLAGS if app.config.get(flag)]
