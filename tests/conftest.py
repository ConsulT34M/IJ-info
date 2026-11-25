"""테스트 공통 픽스처.

기본은 SQLite 메모리다(D20). `TEST_DATABASE_URL`을 주면 그 PostgreSQL로 돌린다(D37).

    TEST_DATABASE_URL=postgresql+psycopg://ekyc:ekyc@127.0.0.1:5432/ekyc_test pytest -q

`@pytest.mark.postgres`가 붙은 테스트는 PostgreSQL에서만 돌고, 아니면 skip된다.
SQLite는 기본적으로 외래키를 보지 않으므로 PRAGMA로 켜서 PostgreSQL과 비슷하게 맞춘다.
"""

from __future__ import annotations

import io
import json
import os
import re
import time
import uuid
from datetime import timedelta

import flask
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
def app(dev_secrets, carrier_cert, tmp_path, monkeypatch):
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
            "CARRIER_CA_BUNDLE": str(carrier_cert["cert"]),
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

    def _post_json(url, body, headers, timeout):
        calls.append(
            {
                "url": url,
                "body": body,
                "headers": headers or {},
                "payload": json.loads(body.decode("utf-8")),
                "timeout": timeout,
            }
        )
        return _Response()

    monkeypatch.setattr("app.api.webhook.post_json", _post_json)
    return calls


@pytest.fixture(scope="session")
def carrier_cert(tmp_path_factory):
    """자체 서명 인증서를 세션당 한 번 만든다(인증서 고정 테스트용)."""
    from carrier.make_certs import make_self_signed

    directory = tmp_path_factory.mktemp("carrier-certs")
    cert_path = directory / "carrier.crt"
    key_path = directory / "carrier.key"
    make_self_signed(cert_path, key_path)
    return {"cert": cert_path, "key": key_path}


@pytest.fixture
def carrier_app(dev_secrets, tmp_path, people):
    """가입자 명부가 적재된 모의 통신사 앱."""
    from carrier import create_carrier_app
    from carrier.models import db as carrier_db
    from carrier.seed import seed_client, seed_subscribers

    application = create_carrier_app(
        {"TESTING": True}, instance_path=str(tmp_path / "carrier-instance")
    )
    # 컨텍스트를 열어 둔 채로 yield하면 A사 앱의 db 세션과 섞인다. 적재만 하고 바로 닫는다.
    with application.app_context():
        carrier_db.create_all()
        seed_subscribers(people)
        seed_client()
        carrier_db.session.commit()
        carrier_db.session.remove()
    return application


@pytest.fixture
def carrier_backend(app, carrier_app, monkeypatch):
    """A사의 통신사 호출을 모의 통신사 앱으로 보낸다(TLS 없이 같은 JSON 계약으로)."""
    from urllib.parse import urlparse

    calls: list[dict] = []

    class _Response:
        def __init__(self, status_code: int, body: bytes):
            self.status_code = status_code
            self._body = body

        def json(self):
            return json.loads(self._body.decode("utf-8"))

    def _post_json(url, payload, headers, timeout, verify):
        calls.append(
            {"url": url, "payload": payload, "headers": headers or {}, "timeout": timeout, "verify": verify}
        )
        with carrier_app.test_client() as carrier_http:
            response = carrier_http.post(urlparse(url).path, json=payload, headers=headers)
            return _Response(response.status_code, response.get_data())

    monkeypatch.setattr("app.common.carrier.post_json", _post_json)
    return calls


@pytest.fixture
def flow(client, api_post, app):
    """인증창 흐름을 단계별로 진행하는 도우미."""

    class Flow:
        def __init__(self):
            self.verification_id = None
            self._csrf_token = None

        def start(self, client_user_ref: str = "user-0001", return_url: str | None = None):
            payload = {
                "client_user_ref": client_user_ref,
                "return_url": return_url or "http://127.0.0.1:9000/done",
            }
            body = api_post("/api/v1/verifications", payload).get_json()
            self.verification_id = uuid.UUID(body["verification_id"])
            token = body["auth_url"].rsplit("/", 1)[-1]
            assert client.get(f"/verify/start/{token}").status_code == 302
            page = client.get("/verify/consent")
            self._csrf_token = re.search(
                r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)
            ).group(1)
            return self.verification_id

        @property
        def csrf_token(self) -> str | None:
            """실제 HTTP 요청으로 폼을 보낼 때 쓴다(동시성 테스트)."""
            return self._csrf_token

        def post(self, path: str, data: dict | None = None, **kwargs):
            payload = dict(data or {})
            payload.setdefault("csrf_token", self._csrf_token)
            return client.post(path, data=payload, **kwargs)

        def consent(self):
            versions = app.config["CONSENT_VERSIONS"]
            data = {name: "on" for name in versions}
            data.update({f"{name}_version": value for name, value in versions.items()})
            return self.post("/verify/consent", data)

        def to_phone(self, **kwargs):
            self.start(**kwargs)
            assert self.consent().status_code == 302
            return self.verification_id

        def request_otp(self, name: str, phone_number: str):
            return self.post("/verify/phone/otp", {"name": name, "phone_number": phone_number})

        def resend_otp(self):
            return self.post("/verify/phone/otp", {"resend": "1"})

        def confirm_otp(self, code: str):
            return self.post("/verify/phone/confirm", {"code": code})

        def to_id_card(self, person: dict, **kwargs):
            """휴대폰 본인확인까지 마치고 stage=ID_CARD 상태로 만든다."""
            self.to_phone(**kwargs)
            assert self.request_otp(person["name"], person["phone_number"]).status_code == 200
            code = self.inbox_code(person["inbox_key"])
            assert self.confirm_otp(code).status_code == 302
            return self.verification_id

        def upload_id_card(self, filename: str = "id_card.png", data: bytes | None = None):
            """IA-07 신분증 이미지 업로드."""
            payload = data if data is not None else sample_png()
            return self.post(
                "/verify/id-card",
                {"image": (io.BytesIO(payload), filename)},
                content_type="multipart/form-data",
            )

        def to_face(self, person: dict, **kwargs):
            """신분증 단계까지 마치고 stage=FACE 상태로 만든다."""
            self.to_id_card(person, **kwargs)
            assert self.upload_id_card().status_code == 302
            assert self.submit_id_info(person["rrn"], person["issue_date"]).status_code == 302
            return self.verification_id

        def upload_face(self, filename: str = "selfie.png", data: bytes | None = None):
            """IA-09 얼굴 사진 업로드."""
            payload = data if data is not None else sample_png()
            return self.post(
                "/verify/face",
                {"image": (io.BytesIO(payload), filename)},
                content_type="multipart/form-data",
            )

        def submit_id_info(self, rrn: str, issue_date: str, name: str = "무시되는이름"):
            """IA-08 신분증 정보 입력. 화면과 같이 앞 6자리·뒤 7자리로 나눠 보낸다(D79)."""
            digits = re.sub(r"[\s-]", "", rrn or "")
            return self.post(
                "/verify/id-confirm",
                {
                    "rrn_front": digits[:6],
                    "rrn_back": digits[6:],
                    "issue_date": issue_date,
                    "name": name,
                },
            )

        def inbox_code(self, inbox_key: str) -> str | None:
            response = client.post("/test-inbox/latest", data={"inbox_key": inbox_key, "csrf_token": self._csrf_token})
            found = re.search(r'class="display-6 mb-1">(\d{6})<', response.get_data(as_text=True))
            return found.group(1) if found else None

    return Flow()


@pytest.fixture
def seeded(app, people):
    """A사 쪽 진위확인 대장·테스트 수신함 적재 (flask seed와 같은 내용)."""
    from app.cli import seed_people

    seed_people(people)
    db.session.commit()
    return people


def sample_png() -> bytes:
    """매직바이트가 맞는 작은 PNG (tools/make_sample_images.py와 같은 코드를 쓴다)."""
    from tools.make_sample_images import make_png

    return make_png((200, 200, 200))


def sample_jpg() -> bytes:
    from tools.make_sample_images import make_jpg

    return make_jpg()


@pytest.fixture
def live_server():
    """WSGI 앱을 실제 HTTP 서버로 띄운다(동시 요청 테스트용)."""
    import threading

    from werkzeug.serving import make_server

    started: list[tuple] = []

    def _start(application) -> str:
        server = make_server("127.0.0.1", 0, application, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started.append((server, thread))
        return f"http://127.0.0.1:{server.port}"

    yield _start

    for server, thread in started:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def make_admin(app):
    """관리자 계정을 만든다(비밀번호·TOTP 시크릿을 함께 돌려준다)."""
    import bcrypt
    import pyotp

    from app.common.crypto import aad, encrypt_str
    from app.models import Admin

    def _make(
        login_id: str = "admin1",
        role: str = "admin",
        password: str = "verylongpassword1",
        allowed_ips: tuple[str, ...] = ("127.0.0.1",),
    ) -> dict:
        admin_id = uuid.uuid4()
        secret = pyotp.random_base32()
        row = Admin(
            id=admin_id,
            login_id=login_id,
            password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            otp_secret=encrypt_str(
                secrets_mod.get_key("ekyc/admin-otp-key"),
                secret,
                aad("admins", "otp_secret", admin_id),
            ),
            role=role,
            allowed_ips=list(allowed_ips),
        )
        db.session.add(row)
        db.session.commit()
        return {"admin": row, "password": password, "secret": secret, "totp": pyotp.TOTP(secret)}

    return _make


@pytest.fixture
def admin_session(app, make_admin):
    """로그인(ID/PW + TOTP)까지 마친 관리자 클라이언트를 만든다."""

    def _login(**kwargs) -> dict:
        account = make_admin(**kwargs)
        http = app.test_client()
        # 테스트는 앱 컨텍스트를 공유하므로 g에 캐시된 CSRF 토큰을 버려야
        # 이 클라이언트의 세션에 새 토큰이 심긴다(운영에서는 요청마다 g가 새로 생긴다)
        flask.g.pop("csrf_token", None)
        page = http.get("/admin/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
        first = http.post(
            "/admin/login",
            data={
                "login_id": account["admin"].login_id,
                "password": account["password"],
                "csrf_token": token,
            },
        )
        assert first.status_code == 302, first.get_data(as_text=True)[:400]
        second = http.post("/admin/otp", data={"code": account["totp"].now(), "csrf_token": token})
        assert second.status_code == 302, second.get_data(as_text=True)[:400]
        account["http"] = http
        account["csrf"] = token
        return account

    return _login
