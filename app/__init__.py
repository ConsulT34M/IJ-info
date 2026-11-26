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
from app.admin.auth import login_manager
from app.common.face import build_face_matcher
from app.common.log_mask import install_masking_filter
from app.common.storage import build_storage
from app.common.timeutil import kst_display
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
    login_manager.init_app(app)
    # 화면·다운로드의 모든 시각은 KST(+09:00)로 표시한다(D73)
    app.jinja_env.filters["kst"] = kst_display

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
        local_widget = (
            app.config["EKYC_ENV"] != "production"
            and (
                request.endpoint == "test_inbox.widget"
                or (request.endpoint == "test_inbox.register_device" and request.args.get("widget") == "1")
            )
        )
        if local_widget:
            # 인증번호는 IJ-info의 등록된 기기 세션에만 보이고, RKX는 iframe 내용을 읽지 못한다.
            response.headers["Content-Security-Policy"] = app.config["CONTENT_SECURITY_POLICY"].replace(
                "frame-ancestors 'none'", "frame-ancestors http://localhost:3000 http://127.0.0.1:3000"
            )
            response.headers.pop("X-Frame-Options", None)
        else:
            response.headers.setdefault("Content-Security-Policy", app.config["CONTENT_SECURITY_POLICY"])
            response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
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
    from app.admin import bp as admin_bp
    from app.api import bp as api_bp
    from app.site import bp as site_bp
    from app.test_inbox import bp as test_inbox_bp
    from app.verify import bp as verify_bp

    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)
    app.register_blueprint(verify_bp)
    app.register_blueprint(test_inbox_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(site_bp)  # 공개 회사 홈페이지. 마지막에 등록해 '/'를 잡는다


# 이용자에게 보여줄 오류 문구. 내부 사정은 드러내지 않는다.
# 공개 홈페이지(site)용 오류 문구. 인증창 문구와 말투가 다르다.
SITE_ERROR_MESSAGES = {
    400: ("잘못된 요청입니다", "입력하신 값을 확인하고 다시 시도해 주세요."),
    403: ("접근할 수 없습니다", "권한이 없는 요청입니다."),
    404: ("페이지를 찾을 수 없습니다", "주소가 변경되었거나 삭제된 페이지입니다. 홈에서 다시 찾아 주세요."),
    405: ("허용되지 않은 방식입니다", "올바른 경로로 다시 요청해 주세요."),
    429: ("요청이 너무 많습니다", "잠시 후 다시 시도해 주세요."),
    500: ("일시적인 오류가 발생했습니다", "잠시 후 다시 시도해 주세요. 계속되면 고객지원으로 알려 주세요."),
}

ERROR_MESSAGES = {
    400: "입력하신 값을 확인해 주세요.",
    401: "인증에 실패했습니다.",
    403: "지금 단계에서는 진행할 수 없는 요청입니다.",
    404: "요청하신 내역을 찾을 수 없습니다.",
    409: "이미 종료된 인증입니다. 이용하시던 서비스에서 다시 시작해 주세요.",
    410: "인증 제한 시간이 지났거나 이미 사용된 주소입니다. 이용하시던 서비스에서 다시 시작해 주세요.",
    413: "파일 용량이 너무 큽니다.",
    429: "잠시 후 다시 시도해 주세요.",
    500: "처리 중 문제가 발생했습니다.",
    503: "현재 이용할 수 없습니다.",
}


def _register_error_handlers(app: Flask) -> None:
    """api는 JSON, 인증창은 화면으로 돌려준다."""

    @app.errorhandler(HTTPException)
    def _handle(exc: HTTPException):
        code = exc.code or 500
        message = exc.description if _has_custom_description(exc) else ERROR_MESSAGES.get(code, exc.name)
        if request.blueprint == "api" or request.path.startswith("/api/"):
            return jsonify(error=exc.name, code=code, message=message), code
        if request.blueprint in (None, "site"):
            # 공개 홈페이지와 없는 주소는 회사 사이트 모양으로 돌려준다(D83)
            heading, site_message = SITE_ERROR_MESSAGES.get(
                code, ("요청을 처리할 수 없다", message)
            )
            return (
                render_template(
                    "site/error.html", code=code, heading=heading, message=site_message
                ),
                code,
            )
        return render_template("error.html", code=code, message=message), code


def _has_custom_description(exc: HTTPException) -> bool:
    """abort(..., description=...)로 직접 넣은 문구인지 본다."""
    default = HTTPException(description=None).description
    return bool(exc.description) and exc.description != default and len(exc.description) < 200


def _register_cli(app: Flask) -> None:
    from app import cli

    cli.register(app)
