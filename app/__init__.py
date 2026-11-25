"""create_app: Flask 앱 조립.

- 서버 사이드 세션(Flask-Session). 쿠키에는 세션 ID만 담긴다.
- 브라우저 폼은 CSRF 보호, api Blueprint는 서명으로 보호하므로 CSRF exempt.
- 로그에는 마스킹 필터를 건다.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_migrate import Migrate
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

from app.common import secrets as secret_store
from app.common.log_mask import install_masking_filter
from app.config import enabled_vuln_flags, init_app_config
from app.models import db

migrate = Migrate()
csrf = CSRFProtect()
server_session = Session()


def create_app(
    config_overrides: dict | None = None,
    instance_path: str | None = None,
) -> Flask:
    """앱을 만든다. 테스트는 config_overrides·instance_path로 덮어쓴다."""
    load_dotenv()

    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    os.makedirs(app.instance_path, mode=0o700, exist_ok=True)
    _ensure_dev_secrets()

    init_app_config(app, config_overrides)
    _configure_logging(app)

    db.init_app(app)
    migrate.init_app(app, db)
    server_session.init_app(app)
    csrf.init_app(app)

    os.makedirs(app.config["UPLOAD_DIR"], mode=0o700, exist_ok=True)

    _register_security_headers(app)
    _register_blueprints(app)
    _register_cli(app)

    flags = enabled_vuln_flags(app)
    if flags:
        app.logger.warning("취약 플래그가 켜져 있다(실습 전용): %s", ", ".join(flags))

    return app


def _ensure_dev_secrets() -> None:
    """D21: dev에서 시크릿 파일이 없으면 만들어 준다. production에서는 만들지 않는다."""
    if os.environ.get("EKYC_ENV", "dev").strip().lower() == "production":
        return
    if not secret_store.secrets_path().exists():
        secret_store.generate_dev_secrets()


def _configure_logging(app: Flask) -> None:
    """마스킹 필터를 걸고 로그 수준을 맞춘다."""
    level = logging.DEBUG if app.config["EKYC_ENV"] != "production" else logging.INFO
    if not app.logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
        app.logger.addHandler(handler)
    app.logger.setLevel(level)
    install_masking_filter(app.logger)
    install_masking_filter(logging.getLogger("werkzeug"))


def _register_security_headers(app: Flask) -> None:
    """W-02 CSP와 기본 보안 헤더."""

    @app.after_request
    def _headers(response):
        response.headers.setdefault("Content-Security-Policy", app.config["CONTENT_SECURITY_POLICY"])
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cache-Control", "no-store")
        if app.config["EKYC_ENV"] == "production":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.route("/healthz")
    def healthz():
        """기동 확인용. 민감한 값은 넣지 않는다."""
        return jsonify(status="ok")


def _register_blueprints(app: Flask) -> None:
    """Blueprint는 구현 단계마다 여기에 추가한다(3단계~)."""
    return None


def _register_cli(app: Flask) -> None:
    from app import cli

    cli.register(app)
