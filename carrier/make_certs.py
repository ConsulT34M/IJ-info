"""모의 통신사용 자체 서명 TLS 인증서 생성.

    python -m carrier.make_certs

carrier/certs/carrier.crt(공개 인증서), carrier.key(개인키)를 만든다. 둘 다 커밋하지 않는다.
A사는 carrier.crt만 신뢰한다(인증서 고정, W-15).
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.common import secrets as secret_store

VALID_DAYS = 365


def make_self_signed(cert_path: Path, key_path: Path) -> None:
    """localhost / 127.0.0.1용 자체 서명 인증서를 만든다."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mock Carrier (lab only)"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
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
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
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
    secret_store.generate_dev_secrets()
    paths = secret_store.get_secret("carrier/tls")
    repo_root = Path(__file__).resolve().parents[1]
    cert_path = repo_root / paths["cert"]
    key_path = repo_root / paths["key"]

    make_self_signed(cert_path, key_path)
    print(f"자체 서명 인증서를 만들었다(유효기간 {VALID_DAYS}일).")
    print(f"  인증서: {cert_path}")
    print(f"  개인키: {key_path}")
    print("A사는 CARRIER_CA_BUNDLE로 이 인증서만 신뢰한다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
