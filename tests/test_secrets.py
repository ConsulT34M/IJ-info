"""시크릿 조회·생성."""

import json
import stat

import pytest

from app.common import secrets as secrets_mod


def test_dev_secrets_cover_all_names(dev_secrets):
    for name in secrets_mod.KEY_SECRET_NAMES:
        assert len(secrets_mod.get_key(name)) == 32
    for name in ("ekyc/db", "ekyc/flask-secret", "ekyc/phone/carrier-client-key", "carrier/tls"):
        assert secrets_mod.get_secret(name)


def test_ci_key_is_shared_between_ekyc_and_carrier(dev_secrets):
    # 이 값이 갈라지면 X-01 대조가 항상 불일치가 된다
    assert secrets_mod.get_key("ekyc/ci-key") == secrets_mod.get_key("carrier/ci-key")


def test_other_keys_are_not_shared(dev_secrets):
    assert secrets_mod.get_key("ekyc/rrn-key") != secrets_mod.get_key("carrier/rrn-key")
    assert secrets_mod.get_key("ekyc/mois-key") != secrets_mod.get_key("ekyc/ci-key")


def test_regenerating_keeps_existing_values(dev_secrets):
    before = secrets_mod.get_key("ekyc/ci-key")
    secrets_mod.generate_dev_secrets()
    assert secrets_mod.get_key("ekyc/ci-key") == before


def test_overwrite_rotates_keys(dev_secrets):
    before = secrets_mod.get_key("ekyc/ci-key")
    secrets_mod.generate_dev_secrets(overwrite=True)
    assert secrets_mod.get_key("ekyc/ci-key") != before


def test_secrets_file_is_owner_only(dev_secrets):
    mode = stat.S_IMODE(secrets_mod.secrets_path().stat().st_mode)
    assert mode == 0o600


def test_put_secret_adds_one_value(dev_secrets):
    secrets_mod.put_secret("ekyc/clients/abc/hmac", "s3cret")
    assert secrets_mod.get_secret("ekyc/clients/abc/hmac") == "s3cret"
    stored = json.loads(secrets_mod.secrets_path().read_text(encoding="utf-8"))
    assert stored["ekyc/clients/abc/hmac"] == "s3cret"
    assert "ekyc/ci-key" in stored


def test_environment_variable_wins(dev_secrets, monkeypatch):
    monkeypatch.setenv("EKYC_SECRET_EKYC_DB", "postgresql+psycopg://x/y")
    assert secrets_mod.get_secret("ekyc/db") == "postgresql+psycopg://x/y"


def test_missing_secret_raises(dev_secrets):
    with pytest.raises(secrets_mod.SecretNotFound):
        secrets_mod.get_secret("ekyc/does-not-exist")
