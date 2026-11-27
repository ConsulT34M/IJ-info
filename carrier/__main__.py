"""모의 통신사 앱 실행.

    python -m carrier            # https://localhost:8443

바인딩 주소·포트는 .env 의 CARRIER_BIND_HOST / CARRIER_PORT 로 바꾼다(기본 127.0.0.1:8443).
다른 호스트나 컨테이너에서 부르려면 CARRIER_BIND_HOST=0.0.0.0 으로 두고,
인증서도 부르는 이름으로 다시 만든다(CARRIER_CERT_HOSTS, carrier/make_certs.py).
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

from app.common import secrets as secret_store
from carrier import DEFAULT_PORT, create_carrier_app
from carrier.models import db


def main() -> int:
    load_dotenv()
    paths = secret_store.get_secret("carrier/tls")
    repo_root = Path(__file__).resolve().parents[1]
    cert = repo_root / paths["cert"]
    key = repo_root / paths["key"]
    if not cert.exists() or not key.exists():
        raise SystemExit("인증서가 없다. 먼저 `python -m carrier.make_certs` 를 돌린다.")

    app = create_carrier_app()
    with app.app_context():
        db.create_all()

    host = os.environ.get("CARRIER_BIND_HOST", "").strip() or "127.0.0.1"
    port = int(os.environ.get("CARRIER_PORT", "").strip() or DEFAULT_PORT)
    app.run(host=host, port=port, ssl_context=(str(cert), str(key)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
