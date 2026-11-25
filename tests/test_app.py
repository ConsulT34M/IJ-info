"""create_app 조립과 기본 보안 설정."""

from app.config import VULN_FLAGS, enabled_vuln_flags


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_security_headers_are_set(client):
    headers = client.get("/healthz").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"


def test_session_is_server_side(app):
    # 쿠키 세션이면 성명·CI가 클라이언트로 나간다. 서버 사이드여야 한다.
    assert app.config["SESSION_TYPE"] == "cachelib"
    assert app.session_interface.__class__.__name__ != "SecureCookieSessionInterface"


def test_session_cookie_flags(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 30 * 60


def test_production_turns_on_secure_cookie(dev_secrets, tmp_path, monkeypatch):
    from app import create_app

    monkeypatch.setenv("EKYC_ENV", "production")
    application = create_app(
        {"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite://"},
        instance_path=str(tmp_path / "prod-instance"),
    )
    assert application.config["SESSION_COOKIE_SECURE"] is True
    assert application.config["WTF_CSRF_SSL_STRICT"] is True
    with application.test_client() as http:
        assert "Strict-Transport-Security" in http.get("/healthz").headers


def test_csrf_protection_is_on(app):
    assert app.config["WTF_CSRF_ENABLED"] is True


def test_all_vuln_flags_default_to_false(app):
    assert len(VULN_FLAGS) == 9  # 14장 6개 + 홈페이지 웹 점검용 3개(D90)
    for flag in VULN_FLAGS:
        assert app.config[flag] is False, flag
    assert enabled_vuln_flags(app) == []


def test_spec_settings_match_chapter_nine(app):
    assert app.config["ENTRY_TOKEN_TTL"].total_seconds() == 600
    assert app.config["VERIFICATION_TTL"].total_seconds() == 1200
    assert app.config["OTP_TTL"].total_seconds() == 180
    assert app.config["OTP_RESEND_INTERVAL"].total_seconds() == 60
    assert app.config["OTP_MAX_ISSUES"] == 5  # D11
    assert app.config["MATCH_MAX_ATTEMPTS"] == 3
    assert app.config["OTP_MAX_ATTEMPTS"] == 3
    assert app.config["FACE_MAX_ATTEMPTS"] == 3
    assert app.config["FACE_SIMILARITY_THRESHOLD"] == 90
    assert app.config["UPLOAD_MAX_BYTES"] == 5 * 1024 * 1024
    assert app.config["CI_RETENTION_AFTER_DELIVERY"].total_seconds() == 7 * 86400
    assert app.config["CI_RETENTION_WITHOUT_DELIVERY"].total_seconds() == 30 * 86400
    assert app.config["ADMIN_MAX_FAILED"] == 5
    assert app.config["ADMIN_LOCK_DURATION"].total_seconds() == 1800
    assert app.config["API_TIMESTAMP_TOLERANCE"] == 300
    assert app.config["WEBHOOK_TIMEOUT"] == 3


def test_upload_dir_is_outside_static_root(app):
    upload_dir = str(app.config["UPLOAD_DIR"])
    assert upload_dir and app.static_folder not in upload_dir
    assert app.config["UPLOAD_DIR"].exists()
