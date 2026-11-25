"""시크릿 조회. 로컬은 instance/dev_secrets.json, 나중에 Secrets Manager로 바꾼다.

호출부는 get_secret(name) / get_key(name)만 쓴다. 저장소가 바뀌어도 이 두 함수만 고친다.
환경변수 EKYC_SECRET_<이름>(대문자, / 와 - 는 _)이 있으면 파일보다 먼저 쓴다.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from app.common.crypto import decode_key, encode_key, generate_key

SECRETS_FILE_ENV = "EKYC_SECRETS_FILE"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SECRETS_FILE = REPO_ROOT / "instance" / "dev_secrets.json"

# 32바이트 키로 생성할 시크릿 (Base64 문자열로 보관)
KEY_SECRET_NAMES = (
    "ekyc/rrn-key",
    "ekyc/mois-key",
    "ekyc/ci-key",
    "ekyc/phone/phone-hmac-key",
    "ekyc/phone/otp-hmac-key",
    "ekyc/phone/inbox-key",
    "ekyc/phone/match-token-key",
    "ekyc/admin-otp-key",
    "carrier/match-hmac-key",
    "carrier/rrn-key",
)

DEFAULT_DB_DSN = "postgresql+psycopg://ekyc:ekyc@127.0.0.1:5432/ekyc"

_cache: dict[str, Any] | None = None


class SecretNotFound(KeyError):
    """없는 시크릿을 찾았다."""


def secrets_path() -> Path:
    """시크릿 파일 경로."""
    return Path(os.environ.get(SECRETS_FILE_ENV) or DEFAULT_SECRETS_FILE)


def _env_name(name: str) -> str:
    return "EKYC_SECRET_" + name.upper().replace("/", "_").replace("-", "_")


def load_secrets(refresh: bool = False) -> dict[str, Any]:
    """시크릿 파일을 읽어 캐시한다."""
    global _cache
    if _cache is None or refresh:
        path = secrets_path()
        if path.exists():
            _cache = json.loads(path.read_text(encoding="utf-8"))
        else:
            _cache = {}
    return _cache


def reset_cache() -> None:
    """테스트에서 시크릿 파일을 바꿔 끼울 때 쓴다."""
    global _cache
    _cache = None


def get_secret(name: str) -> Any:
    """시크릿 값을 돌려준다. 없으면 SecretNotFound."""
    override = os.environ.get(_env_name(name))
    if override is not None:
        return override
    try:
        return load_secrets()[name]
    except KeyError as exc:
        raise SecretNotFound(f"시크릿이 없다: {name}") from exc


def get_key(name: str) -> bytes:
    """Base64로 보관한 32바이트 키를 돌려준다."""
    return decode_key(get_secret(name))


def put_secret(name: str, value: Any) -> None:
    """시크릿 하나를 파일에 추가·갱신한다(flask create-client 등)."""
    path = secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    current[name] = value
    _write(path, current)
    reset_cache()


def generate_dev_secrets(overwrite: bool = False) -> dict[str, Any]:
    """로컬 개발용 시크릿을 만든다. 이미 있는 값은 기본적으로 건드리지 않는다.

    carrier/ci-key는 ekyc/ci-key와 같은 값이어야 CI 대조가 성립한다.
    """
    path = secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    current: dict[str, Any] = {}
    if path.exists() and not overwrite:
        current = json.loads(path.read_text(encoding="utf-8"))

    for key_name in KEY_SECRET_NAMES:
        current.setdefault(key_name, encode_key(generate_key()))
    current["carrier/ci-key"] = current["ekyc/ci-key"]
    current.setdefault("ekyc/db", DEFAULT_DB_DSN)
    current.setdefault("ekyc/flask-secret", encode_key(generate_key()))
    current.setdefault("ekyc/phone/carrier-client-key", encode_key(generate_key()))
    current.setdefault(
        "carrier/tls",
        {"cert": "carrier/certs/carrier.crt", "key": "carrier/certs/carrier.key"},
    )

    _write(path, current)
    reset_cache()
    return current


def _write(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    path.chmod(0o600)
