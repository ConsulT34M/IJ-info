"""flask seed / create-client / create-admin."""

import json

import bcrypt
import pytest

from app.cli import create_admin_command, create_client_command, seed_command
from app.common import secrets as secrets_mod
from app.common.crypto import aad, decrypt_str, hmac_sha256_hex, sha256_hex
from app.common.hmac_auth import api_key_hash
from app.models import Admin, Client, MockMoisRegistry, TestPhone, db


@pytest.fixture
def people_file(tmp_path, people):
    path = tmp_path / "people.json"
    path.write_text(json.dumps({"seed": 1, "people": people}, ensure_ascii=False), encoding="utf-8")
    return path


def test_seed_loads_registry_and_inbox(runner, people_file, people):
    result = runner.invoke(seed_command, ["--people", str(people_file)])
    assert result.exit_code == 0, result.output
    assert "추가 10건" in result.output

    assert db.session.scalar(db.select(db.func.count()).select_from(MockMoisRegistry)) == 10
    assert db.session.scalar(db.select(db.func.count()).select_from(TestPhone)) == 10

    mois_key = secrets_mod.get_key("ekyc/mois-key")
    phone_key_secret = secrets_mod.get_key("ekyc/phone/phone-hmac-key")
    person = people[0]
    entry = db.session.scalars(
        db.select(MockMoisRegistry).filter_by(rrn_hash=hmac_sha256_hex(mois_key, person["rrn"]))
    ).one()
    assert entry.name == person["name"]
    assert entry.status == "정상"

    inbox = db.session.get(TestPhone, hmac_sha256_hex(phone_key_secret, person["phone_number"]))
    assert inbox.inbox_key_hash == sha256_hex(person["inbox_key"])
    assert inbox.phone_mask.endswith(person["phone_number"][-4:])


def test_seed_marks_person_nine_as_lost(runner, people_file, people):
    runner.invoke(seed_command, ["--people", str(people_file)])
    mois_key = secrets_mod.get_key("ekyc/mois-key")
    lost = [p for p in people if p["person_no"] == 9][0]
    entry = db.session.scalars(
        db.select(MockMoisRegistry).filter_by(rrn_hash=hmac_sha256_hex(mois_key, lost["rrn"]))
    ).one()
    assert entry.status == "분실"
    assert db.session.scalar(
        db.select(db.func.count()).select_from(MockMoisRegistry).filter_by(status="분실")
    ) == 1


def test_seed_is_idempotent(runner, people_file):
    runner.invoke(seed_command, ["--people", str(people_file)])
    result = runner.invoke(seed_command, ["--people", str(people_file)])
    assert result.exit_code == 0
    assert "갱신 10건" in result.output
    assert db.session.scalar(db.select(db.func.count()).select_from(MockMoisRegistry)) == 10


def test_seed_output_and_rows_have_no_plaintext(runner, people_file, people):
    result = runner.invoke(seed_command, ["--people", str(people_file)])
    for person in people:
        assert person["rrn"] not in result.output
        assert person["phone_number"] not in result.output
        assert person["inbox_key"] not in result.output
        assert person["name"] not in result.output

    rows = db.session.scalars(db.select(MockMoisRegistry)).all()
    dumped = " ".join(f"{row.name}{row.rrn_hash}{row.issue_date}" for row in rows)
    for person in people:
        assert person["rrn"] not in dumped


def test_seed_without_people_file(runner, tmp_path):
    result = runner.invoke(seed_command, ["--people", str(tmp_path / "nope.json")])
    assert result.exit_code != 0
    assert "make_people" in result.output


def test_create_client_stores_hash_and_prints_secrets_once(runner):
    result = runner.invoke(
        create_client_command,
        ["--name", "SILO", "--callback-url", "http://127.0.0.1:9000/cb", "--allowed-ips", "127.0.0.1,10.0.0.0/24"],
    )
    assert result.exit_code == 0, result.output

    row = db.session.scalars(db.select(Client).filter_by(name="SILO")).one()
    assert row.allowed_ips == ["127.0.0.1", "10.0.0.0/24"]
    assert row.status == "ACTIVE"
    assert row.hmac_secret_ref == f"ekyc/clients/{row.id}/hmac"

    printed_api_key = [
        line.split(":", 1)[1].strip() for line in result.output.splitlines() if "X-Api-Key" in line
    ][0]
    printed_secret = [
        line.split(":", 1)[1].strip() for line in result.output.splitlines() if "HMAC Secret" in line
    ][0]

    # API Key 원문은 DB에 없고 해시만 있다
    assert row.api_key_hash == api_key_hash(printed_api_key)
    assert printed_api_key not in row.api_key_hash
    # HMAC Secret은 시크릿 저장소에만 있다
    assert secrets_mod.get_secret(row.hmac_secret_ref) == printed_secret


def test_create_client_rejects_bad_input(runner):
    bad_url = runner.invoke(
        create_client_command,
        ["--name", "A", "--callback-url", "javascript:alert(1)", "--allowed-ips", "127.0.0.1"],
    )
    assert bad_url.exit_code != 0 and "callback_url" in bad_url.output

    bad_ip = runner.invoke(
        create_client_command,
        ["--name", "A", "--callback-url", "https://a.example/cb", "--allowed-ips", "nope"],
    )
    assert bad_ip.exit_code != 0 and "허용 IP" in bad_ip.output

    empty_ip = runner.invoke(
        create_client_command,
        ["--name", "A", "--callback-url", "https://a.example/cb", "--allowed-ips", " , "],
    )
    assert empty_ip.exit_code != 0


def test_create_client_rejects_duplicate_name(runner):
    args = ["--name", "SILO", "--callback-url", "https://a.example/cb", "--allowed-ips", "127.0.0.1"]
    assert runner.invoke(create_client_command, args).exit_code == 0
    again = runner.invoke(create_client_command, args)
    assert again.exit_code != 0 and "이미 있다" in again.output


def test_create_admin_stores_bcrypt_and_encrypted_totp(runner):
    result = runner.invoke(
        create_admin_command,
        ["--login-id", "auditor1", "--role", "auditor", "--allowed-ips", "127.0.0.1"],
        input="verylongpassword1\nverylongpassword1\n",
    )
    assert result.exit_code == 0, result.output
    assert "otpauth://" in result.output

    row = db.session.scalars(db.select(Admin).filter_by(login_id="auditor1")).one()
    assert row.role == "auditor" and row.failed_count == 0 and row.locked_until is None
    assert row.password_hash.startswith("$2b$")
    assert bcrypt.checkpw(b"verylongpassword1", row.password_hash.encode())
    assert not bcrypt.checkpw(b"wrong-password", row.password_hash.encode())

    # TOTP 시크릿은 암호문으로만 저장되고 admin id에 묶인다(D17)
    secret = decrypt_str(
        secrets_mod.get_key("ekyc/admin-otp-key"),
        row.otp_secret,
        aad("admins", "otp_secret", row.id),
    )
    assert secret in result.output  # 등록 URI에만 들어 있다
    assert secret.encode() not in row.otp_secret


def test_create_admin_rejects_short_password_and_duplicates(runner):
    short = runner.invoke(
        create_admin_command,
        ["--login-id", "admin1", "--allowed-ips", "127.0.0.1"],
        input="short\nshort\n",
    )
    assert short.exit_code != 0 and "12자" in short.output

    args = ["--login-id", "admin1", "--allowed-ips", "127.0.0.1"]
    assert runner.invoke(create_admin_command, args, input="verylongpassword1\nverylongpassword1\n").exit_code == 0
    again = runner.invoke(create_admin_command, args, input="verylongpassword1\nverylongpassword1\n")
    assert again.exit_code != 0 and "이미 있다" in again.output
