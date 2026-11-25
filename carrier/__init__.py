"""모의 통신사 앱 (A사와 별도 Flask 앱 + SQLite).

로컬에서 https://localhost:8443 로 띄운다. 자체 서명 인증서는 carrier/make_certs.py로 만들고
A사는 그 인증서 파일만 신뢰한다(인증서 고정).
"""

from __future__ import annotations

import logging
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from app.common import secrets as secret_store
from app.common.log_mask import install_masking_filter
from carrier.models import db

DEFAULT_PORT = 8443


def create_carrier_app(config_overrides: dict | None = None, instance_path: str | None = None) -> Flask:
    """모의 통신사 앱을 만든다."""
    load_dotenv()

    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    os.makedirs(app.instance_path, mode=0o700, exist_ok=True)
    if not secret_store.secrets_path().exists():
        secret_store.generate_dev_secrets()

    app.config.update(
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(app.instance_path) / 'carrier.sqlite3'}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MATCH_TOKEN_TTL=timedelta(minutes=5),  # 대조 토큰 5분
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if config_overrides:
        app.config.update(config_overrides)

    app.json.sort_keys = False
    db.init_app(app)

    if not app.logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s carrier: %(message)s"))
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    install_masking_filter(app.logger)

    from carrier.routes import bp

    app.register_blueprint(bp)

    @app.errorhandler(HTTPException)
    def _json_error(exc: HTTPException):
        return jsonify(error=exc.name, code=exc.code, message=exc.description), exc.code or 500

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.after_request
    def _headers(response):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response

    return app
