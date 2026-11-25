"""테스트 공통 픽스처.

기본은 SQLite 메모리다(D20). `TEST_DATABASE_URL`을 주면 그 PostgreSQL로 돌린다(D37).

    TEST_DATABASE_URL=postgresql+psycopg://ekyc:ekyc@127.0.0.1:5432/ekyc_test pytest -q

`@pytest.mark.postgres`가 붙은 테스트는 PostgreSQL에서만 돌고, 아니면 skip된다.
SQLite는 기본적으로 외래키를 보지 않으므로 PRAGMA로 켜서 PostgreSQL과 비슷하게 맞춘다.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import timedelta

import pytest
import sqlalchemy as sa

from app import create_app
from app.common import secrets as secrets_mod
from app.common.hmac_auth import (
    api_key_hash,
    build_signature,
    generate_api_key,
    generate_hmac_secret,
)
from app.common.timeutil import now_utc
from app.config import VULN_FLAGS
from app.models import Client, Verification, db
from seed.make_people import make_people


def test_database_url() -> str | None:
    """PostgreSQL로 테스트할 때의 DSN. 없으면 SQLite 메모리를 쓴다."""
    return os.environ.get("TEST_DATABASE_URL") or None


def pytest_collection_modifyitems(config, items):
    """PostgreSQL 전용 테스트는 SQLite로 돌릴 때 건너뛴다."""
    if test_database_url():
        return
    skip_marker = pytest.mark.skip(
        reason="PostgreSQL 전용 테스트다. TEST_DATABASE_URL을 설정하고 돌린다."
    )
    for item in items:
        if "postgres" in item.keywords:
            item.add_marker(skip_marker)


@pytest.fixture(scope="session", autouse=True)
def _database_schema():
    """PostgreSQL로 돌릴 때는 스키마를 세션 시작에 한 번만 만든다."""
    url = test_database_url()
    if not url:
        yield
        return
    engine = sa.create_engine(url)
    db.metadata.drop_all(engine)
    db.metadata.create_all(engine)
    yield
    db.metadata.drop_all(engine)
    engine.dispose()


def _truncate_all() -> None:
    """테스트마다 모든 테이블을 비운다(PostgreSQL)."""
    names = ", ".join(f'"{name}"' for name in db.metadata.tables)
    db.session.execute(sa.text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
    db.session.commit()


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

    url = test_database_url()
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": url or "sqlite://",
            "UPLOAD_DIR": tmp_path / "uploads",
            "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
        },
        instance_path=str(tmp_path / "instance"),
    )

    with application.app_context():
        if url:
            _truncate_all()
        else:
            sa.event.listen(db.engine, "connect", _enable_sqlite_foreign_keys)
            db.engine.dispose()  # 이미 열린 연결에도 PRAGMA가 걸리게 다시 연다
            db.create_all()
        yield application
        db.session.remove()
        if not url:
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


@pytest.fixture
def sign_headers(exchange_client):
    """위탁사 서명 헤더를 만든다."""

    def _headers(body: bytes = b"", *, timestamp: int | None = None, api_key: str | None = None):
        stamp = str(timestamp if timestamp is not None else int(time.time()))
        return {
            "X-Api-Key": api_key if api_key is not None else exchange_client["api_key"],
            "X-Timestamp": stamp,
            "X-Signature": build_signature(exchange_client["hmac_secret"], stamp, body),
            "Content-Type": "application/json",
        }

    return _headers


@pytest.fixture
def api_post(client, sign_headers):
    """IA-01처럼 서명이 필요한 POST를 보낸다."""

    def _post(path: str, payload: dict | None = None, **kwargs):
        body = json.dumps(payload or {}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = sign_headers(body, **kwargs)
        return client.post(path, data=body, headers=headers)

    return _post


@pytest.fixture
def sent_webhooks(monkeypatch):
    """IA-11 전송을 가로채 payload를 모아 둔다. 항상 200으로 응답한다."""
    calls: list[dict] = []

    class _Response:
        status_code = 200

    def _post(url, data=None, headers=None, timeout=None):
        calls.append(
            {
                "url": url,
                "body": data,
                "headers": headers or {},
                "payload": json.loads(data.decode("utf-8")),
                "timeout": timeout,
            }
        )
        return _Response()

    monkeypatch.setattr("app.api.webhook.requests.post", _post)
    return calls
