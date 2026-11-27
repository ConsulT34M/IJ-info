"""모의 통신사용 자체 서명 TLS 인증서 생성.

    python -m carrier.make_certs

carrier/certs/carrier.crt(공개 인증서), carrier.key(개인키)를 만든다. 둘 다 커밋하지 않는다.
A사는 carrier.crt만 신뢰한다(인증서 고정, W-15).

인증서에 넣을 이름은 .env 의 CARRIER_CERT_HOSTS(쉼표 구분)로 정한다. 기본값은 호스트 실행
(localhost), 컨테이너에서 호스트 통신사 호출(host.docker.internal), compose 통신사 서비스
(carrier) 세 경우를 모두 담는다.
A사가 CARRIER_BASE_URL 에 쓰는 호스트 이름이 여기 들어 있어야 TLS 검증을 통과한다.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.common import secrets as secret_store

VALID_DAYS = 365
DEFAULT_CERT_HOSTS = ("localhost", "127.0.0.1", "host.docker.internal", "carrier")


def cert_hosts() -> list[str]:
    """인증서에 넣을 호스트 이름·IP 목록. CARRIER_CERT_HOSTS가 없으면 로컬 기본값."""
    raw = os.environ.get("CARRIER_CERT_HOSTS", "")
    hosts = [item.strip() for item in raw.split(",") if item.strip()]
    return hosts or list(DEFAULT_CERT_HOSTS)


def _alt_name(host: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


def make_self_signed(cert_path: Path, key_path: Path, hosts: list[str] | None = None) -> None:
    """자체 서명 인증서를 만든다. hosts가 없으면 DEFAULT_CERT_HOSTS."""
    hosts = hosts or list(DEFAULT_CERT_HOSTS)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mock Carrier (lab only)"),
            x509.NameAttribute(NameOID.COMMON_NAME, hosts[0]),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(
            x509.SubjectAlternativeName([_alt_name(host) for host in hosts]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)


def main() -> int:
    load_dotenv()
    secret_store.generate_dev_secrets()
    paths = secret_store.get_secret("carrier/tls")
    repo_root = Path(__file__).resolve().parents[1]
    cert_path = repo_root / paths["cert"]
    key_path = repo_root / paths["key"]

    hosts = cert_hosts()
    make_self_signed(cert_path, key_path, hosts)
    print(f"자체 서명 인증서를 만들었다(유효기간 {VALID_DAYS}일).")
    print(f"  이름  : {', '.join(hosts)}")
    print(f"  인증서: {cert_path}")
    print(f"  개인키: {key_path}")
    print("A사는 CARRIER_CA_BUNDLE로 이 인증서만 신뢰한다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
