"""모의 통신사 앱 실행.

    python -m carrier            # https://localhost:8443
"""

from __future__ import annotations

from pathlib import Path

from app.common import secrets as secret_store
from carrier import DEFAULT_PORT, create_carrier_app
from carrier.models import db


def main() -> int:
    paths = secret_store.get_secret("carrier/tls")
    repo_root = Path(__file__).resolve().parents[1]
    cert = repo_root / paths["cert"]
    key = repo_root / paths["key"]
    if not cert.exists() or not key.exists():
        raise SystemExit("인증서가 없다. 먼저 `python -m carrier.make_certs` 를 돌린다.")

    app = create_carrier_app()
    with app.app_context():
        db.create_all()

    app.run(host="127.0.0.1", port=DEFAULT_PORT, ssl_context=(str(cert), str(key)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
