"""테스트 공통 픽스처.

DB는 SQLite 메모리로 돌린다(D20). docker 없이도 테스트가 돈다.
SQLite는 기본적으로 외래키를 보지 않으므로 PRAGMA로 켜서 PostgreSQL과 비슷하게 맞춘다.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
import sqlalchemy as sa

from app import create_app
from app.common import secrets as secrets_mod
from app.common.hmac_auth import api_key_hash, generate_api_key, generate_hmac_secret
from app.common.timeutil import now_utc
from app.config import VULN_FLAGS
from app.models import Client, Verification, db
from seed.make_people import make_people


def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:
    """SQLite는 기본적으로 외래키를 보지 않는다."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture
def dev_secrets(tmp_path, monkeypatch):
    """임시 디렉터리에 개발용 시크릿을 만들고 그걸 쓰게 한다."""
    monkeypatch.setenv("EKYC_SECRETS_FILE", str(tmp_path / "dev_secrets.json"))
    secrets_mod.reset_cache()
    data = secrets_mod.generate_dev_secrets()
    yield data
    secrets_mod.reset_cache()


@pytest.fixture(scope="session")
def people():
    """가상 인물 10명(고정 시드)."""
    return make_people()


@pytest.fixture
def app(dev_secrets, tmp_path, monkeypatch):
    """SQLite 메모리 DB를 쓰는 앱. 취약 플래그는 전부 꺼진 상태로 시작한다."""
    monkeypatch.setenv("EKYC_ENV", "dev")
    for flag in VULN_FLAGS:
        monkeypatch.setenv(flag, "false")

    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "UPLOAD_DIR": tmp_path / "uploads",
        },
        instance_path=str(tmp_path / "instance"),
    )

    with application.app_context():
        sa.event.listen(db.engine, "connect", _enable_sqlite_foreign_keys)
        db.engine.dispose()  # 이미 열린 연결에도 PRAGMA가 걸리게 다시 연다
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """HTTP 테스트 클라이언트."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """flask CLI 테스트 러너."""
    return app.test_cli_runner()


@pytest.fixture
def exchange_client(app):
    """위탁사(거래소) 한 곳을 등록해 둔다. api_key·hmac_secret 원문을 함께 돌려준다."""
    api_key = generate_api_key()
    hmac_secret = generate_hmac_secret()
    client_id = uuid.uuid4()
    secret_ref = f"ekyc/clients/{client_id}/hmac"
    secrets_mod.put_secret(secret_ref, hmac_secret)

    row = Client(
        id=client_id,
        name="SILO 거래소",
        api_key_hash=api_key_hash(api_key),
        hmac_secret_ref=secret_ref,
        callback_url="http://127.0.0.1:9000/callback",
        allowed_ips=["127.0.0.1"],
        status="ACTIVE",
    )
    db.session.add(row)
    db.session.commit()
    return {"client": row, "api_key": api_key, "hmac_secret": hmac_secret}


@pytest.fixture
def make_verification(app, exchange_client):
    """진행 중인 인증 건을 만든다."""

    def _make(**overrides):
        created = now_utc()
        values = {
            "client_id": exchange_client["client"].id,
            "client_user_ref": "user-0001",
            "return_url": "http://127.0.0.1:9000/done",
            "created_at": created,
            "expires_at": created + timedelta(minutes=20),
        }
        values.update(overrides)
        row = Verification(**values)
        db.session.add(row)
        db.session.commit()
        return row

    return _make
