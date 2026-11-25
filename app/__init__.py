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
from flask import Flask, jsonify, render_template, request
from flask_migrate import Migrate
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException

from app.common import secrets as secret_store
from app.common.face import build_face_matcher
from app.common.log_mask import install_masking_filter
from app.common.storage import build_storage
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
    app.json.sort_keys = False  # 응답 필드 순서를 명세와 같게 둔다
    _configure_logging(app)

    db.init_app(app)
    migrate.init_app(app, db)
    server_session.init_app(app)
    csrf.init_app(app)

    os.makedirs(app.config["UPLOAD_DIR"], mode=0o700, exist_ok=True)
    app.extensions["storage"] = build_storage(app.config)
    app.extensions["face_matcher"] = build_face_matcher(app.config)

    _register_security_headers(app)
    _register_error_handlers(app)
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
    """Blueprint 등록. api는 HMAC 서명으로 보호하므로 CSRF를 면제한다."""
    from app.api import bp as api_bp
    from app.test_inbox import bp as test_inbox_bp
    from app.verify import bp as verify_bp

    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)
    app.register_blueprint(verify_bp)
    app.register_blueprint(test_inbox_bp)


# 이용자에게 보여줄 오류 문구. 내부 사정은 드러내지 않는다.
ERROR_MESSAGES = {
    400: "입력값을 확인한다.",
    401: "인증에 실패했다.",
    403: "지금 단계에서는 할 수 없는 요청이다.",
    404: "요청한 건을 찾을 수 없다.",
    409: "이미 끝난 건이다. 거래소에서 다시 시작한다.",
    410: "인증 제한 시간이 지났거나 이미 사용한 주소다. 거래소에서 다시 시작한다.",
    413: "파일이 너무 크다.",
    429: "잠시 후 다시 시도한다.",
    500: "처리 중 문제가 생겼다.",
    503: "아직 사용할 수 없는 기능이다.",
}


def _register_error_handlers(app: Flask) -> None:
    """api는 JSON, 인증창은 화면으로 돌려준다."""

    @app.errorhandler(HTTPException)
    def _handle(exc: HTTPException):
        code = exc.code or 500
        message = exc.description if _has_custom_description(exc) else ERROR_MESSAGES.get(code, exc.name)
        if request.blueprint == "api" or request.path.startswith("/api/"):
            return jsonify(error=exc.name, code=code, message=message), code
        return render_template("error.html", code=code, message=message), code


def _has_custom_description(exc: HTTPException) -> bool:
    """abort(..., description=...)로 직접 넣은 문구인지 본다."""
    default = HTTPException(description=None).description
    return bool(exc.description) and exc.description != default and len(exc.description) < 200


def _register_cli(app: Flask) -> None:
    from app import cli

    cli.register(app)
