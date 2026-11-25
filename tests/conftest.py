"""테스트 공통 픽스처."""

import pytest

from app.common import secrets as secrets_mod
from seed.make_people import make_people


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
