"""flask CLI 명령.

    flask seed           개발용 시크릿 생성 + 진위확인 대장·테스트 수신함 적재
    flask create-client  위탁사 등록 (API Key·HMAC Secret은 이때 한 번만 출력)
    flask create-admin   관리자 등록 (TOTP 등록 URI 출력)
"""

from __future__ import annotations

import ipaddress
import json
import sys
import uuid
from datetime import date
from pathlib import Path
import bcrypt
import click
import pyotp
from flask import current_app
from flask.cli import with_appcontext

from app.common import secrets as secret_store
from app.common.audit import log_access, log_phone_event
from app.common.crypto import aad, encrypt_str, hmac_sha256_hex, sha256_hex
from app.common.images import delete_verification_images
from app.common.timeutil import kst_display, now_utc
from app.common.hmac_auth import api_key_hash, generate_api_key, generate_hmac_secret
from app.common.log_mask import mask_name, mask_phone, mask_rrn
from app.common.rrn import normalize_rrn
from app.common.urls import allowed_schemes, parse_absolute_url
from app.models import (
    Admin,
    Client,
    FaceCheck,
    IdDocument,
    MockMoisRegistry,
    PhoneVerification,
    TestPhone,
    Verification,
    db,
)

PEOPLE_FILE = Path(__file__).resolve().parents[1] / "seed" / "people.json"


def register(app) -> None:
    app.cli.add_command(seed_command)
    app.cli.add_command(create_client_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(purge_command)
    app.cli.add_command(expire_command)


def _load_people(path: Path) -> list[dict]:
    if not path.exists():
        raise click.ClickException(
            f"{path} 가 없다. 먼저 `python seed/make_people.py` 를 돌린다."
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["people"] if isinstance(data, dict) else data


def _parse_ips(raw: str) -> list[str]:
    entries = [item.strip() for item in raw.split(",") if item.strip()]
    if not entries:
        raise click.ClickException("허용 IP를 하나 이상 넣는다(빈 목록은 전부 거부된다).")
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise click.ClickException(f"허용 IP 형식이 아니다: {entry}") from exc
    return entries


def seed_people(people: list[dict]) -> dict[str, int]:
    """진위확인 대장과 테스트 수신함을 적재한다(commit은 호출부에서).

    CLI와 테스트가 같은 코드를 쓰도록 분리했다.
    """
    mois_key = secret_store.get_key("ekyc/mois-key")
    phone_key_secret = secret_store.get_key("ekyc/phone/phone-hmac-key")

    counts = {"mois_added": 0, "mois_updated": 0, "phone_added": 0, "phone_updated": 0}
    for person in people:
        digits = normalize_rrn(person["rrn"])
        if digits is None:
            raise click.ClickException(f"주민번호 형식이 아니다: person_no={person['person_no']}")
        rrn_hash = hmac_sha256_hex(mois_key, digits)

        entry = db.session.scalars(
            db.select(MockMoisRegistry).filter_by(rrn_hash=rrn_hash)
        ).one_or_none()
        if entry is None:
            db.session.add(
                MockMoisRegistry(
                    name=person["name"],
                    rrn_hash=rrn_hash,
                    issue_date=date.fromisoformat(person["issue_date"]),
                    status=person["mois_status"],
                )
            )
            counts["mois_added"] += 1
        else:
            entry.name = person["name"]
            entry.issue_date = date.fromisoformat(person["issue_date"])
            entry.status = person["mois_status"]
            counts["mois_updated"] += 1

        phone_digits = person["phone_number"]
        phone_key = hmac_sha256_hex(phone_key_secret, phone_digits)
        phone = db.session.get(TestPhone, phone_key)
        if phone is None:
            db.session.add(
                TestPhone(
                    phone_key=phone_key,
                    phone_mask=mask_phone(phone_digits),
                    inbox_key_hash=sha256_hex(person["inbox_key"]),
                    next_issue_at=None,
                )
            )
            counts["phone_added"] += 1
        else:
            phone.phone_mask = mask_phone(phone_digits)
            phone.inbox_key_hash = sha256_hex(person["inbox_key"])
            counts["phone_updated"] += 1

    return counts


@click.command("seed")
@click.option("--people", "people_path", type=Path, default=PEOPLE_FILE, show_default=True)
@with_appcontext
def seed_command(people_path: Path) -> None:
    """개발용 시크릿을 만들고 진위확인 대장·테스트 수신함을 적재한다."""
    secret_store.generate_dev_secrets()
    click.echo(f"시크릿 확인: {secret_store.secrets_path()}")

    people = _load_people(people_path)
    counts = seed_people(people)
    db.session.commit()

    click.echo(f"진위확인 대장: 추가 {counts['mois_added']}건, 갱신 {counts['mois_updated']}건")
    click.echo(f"테스트 수신함: 추가 {counts['phone_added']}건, 갱신 {counts['phone_updated']}건")
    for person in people:
        click.echo(
            f"  {person['person_no']:>2} {mask_name(person['name'])} "
            f"{mask_rrn(person['rrn'])} {mask_phone(person['phone_number'])} "
            f"{person['mois_status']}"
        )


@click.command("create-client")
@click.option("--name", required=True, help="위탁사 이름")
@click.option("--callback-url", required=True, help="결과 웹훅(IA-11)을 받을 주소")
@click.option("--allowed-ips", required=True, help="허용 IP 목록(쉼표 구분, CIDR 가능)")
@with_appcontext
def create_client_command(name: str, callback_url: str, allowed_ips: str) -> None:
    """위탁사를 등록한다. API Key와 HMAC Secret은 이때 한 번만 출력된다."""
    if parse_absolute_url(callback_url) is None:
        schemes = ", ".join(allowed_schemes())
        raise click.ClickException(f"callback_url이 허용된 절대 주소가 아니다(허용 스킴: {schemes}).")
    ips = _parse_ips(allowed_ips)

    if db.session.scalars(db.select(Client).filter_by(name=name)).one_or_none():
        raise click.ClickException(f"같은 이름의 위탁사가 이미 있다: {name}")

    client_id = uuid.uuid4()
    api_key = generate_api_key()
    hmac_secret = generate_hmac_secret()
    secret_ref = f"ekyc/clients/{client_id}/hmac"
    secret_store.put_secret(secret_ref, hmac_secret)

    db.session.add(
        Client(
            id=client_id,
            name=name,
            api_key_hash=api_key_hash(api_key),
            hmac_secret_ref=secret_ref,
            callback_url=callback_url,
            allowed_ips=ips,
            status="ACTIVE",
        )
    )
    db.session.commit()

    click.echo("위탁사를 등록했다.")
    click.echo(f"  client_id    : {client_id}")
    click.echo(f"  callback_url : {callback_url}")
    click.echo(f"  allowed_ips  : {', '.join(ips)}")
    click.echo("")
    click.echo("아래 두 값은 지금 한 번만 보여준다. 거래소 담당에게 안전한 경로로 전달한다.")
    click.echo(f"  X-Api-Key    : {api_key}")
    click.echo(f"  HMAC Secret  : {hmac_secret}")


@click.command("create-admin")
@click.option("--login-id", required=True)
@click.option("--role", type=click.Choice(["admin", "auditor"]), default="admin", show_default=True)
@click.option("--allowed-ips", required=True, help="관리자별 허용 IP(쉼표 구분, CIDR 가능)")
@click.option(
    "--password-stdin",
    is_flag=True,
    help="비밀번호를 표준입력 첫 줄에서 읽는다(스크립트용). 명령행 인자로는 받지 않는다.",
)
@with_appcontext
def create_admin_command(login_id: str, role: str, allowed_ips: str, password_stdin: bool) -> None:
    """관리자를 등록하고 TOTP 등록 URI를 출력한다."""
    ips = _parse_ips(allowed_ips)
    if db.session.scalars(db.select(Admin).filter_by(login_id=login_id)).one_or_none():
        raise click.ClickException(f"같은 login_id가 이미 있다: {login_id}")

    if password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = click.prompt("비밀번호", hide_input=True, confirmation_prompt=True)
    if len(password) < 12:
        raise click.ClickException("비밀번호는 12자 이상으로 넣는다.")

    admin_id = uuid.uuid4()
    otp_secret = pyotp.random_base32()
    db.session.add(
        Admin(
            id=admin_id,
            login_id=login_id,
            password_hash=bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii"),
            otp_secret=encrypt_str(
                secret_store.get_key("ekyc/admin-otp-key"),
                otp_secret,
                aad("admins", "otp_secret", admin_id),
            ),
            role=role,
            allowed_ips=ips,
        )
    )
    db.session.commit()

    uri = pyotp.TOTP(otp_secret).provisioning_uri(name=login_id, issuer_name="A사 eKYC 관리자")
    click.echo(f"관리자를 등록했다: {login_id} ({role}), 허용 IP {', '.join(ips)}")
    click.echo("OTP 앱에 아래 URI를 등록한다(지금 한 번만 보여준다).")
    click.echo(f"  {uri}")


@click.command("purge")
@click.option("--dry-run", is_flag=True, help="무엇을 지울지만 보여준다")
@with_appcontext
def purge_command(dry_run: bool) -> None:
    """CI 보관기한이 지난 건의 CI를 파기하고, 종결된 건에 남은 이미지를 지운다(F-14).

    보관기한: 첫 수령 후 7일 / 미수령 시 판정 후 30일.
    VULN_C10을 켜면 DB 참조만 지우고 Storage 객체는 남긴다(실습용).
    """
    now = now_utc()
    after_delivery = now - current_app.config["CI_RETENTION_AFTER_DELIVERY"]
    without_delivery = now - current_app.config["CI_RETENTION_WITHOUT_DELIVERY"]

    expired_ci = db.session.scalars(
        db.select(PhoneVerification)
        .join(Verification, Verification.id == PhoneVerification.verification_id)
        .where(
            PhoneVerification.ci.is_not(None),
            db.or_(
                PhoneVerification.ci_first_delivered_at <= after_delivery,
                db.and_(
                    PhoneVerification.ci_first_delivered_at.is_(None),
                    Verification.completed_at.is_not(None),
                    Verification.completed_at <= without_delivery,
                ),
            ),
        )
    ).all()

    leftover = db.session.scalars(
        db.select(Verification)
        .outerjoin(IdDocument, IdDocument.verification_id == Verification.id)
        .outerjoin(FaceCheck, FaceCheck.verification_id == Verification.id)
        .where(
            Verification.status != "PENDING",
            db.or_(IdDocument.s3_key.is_not(None), FaceCheck.s3_key.is_not(None)),
        )
        .distinct()
    ).all()

    click.echo(f"기준 시각 {kst_display(now)}")
    click.echo(f"CI 파기 대상 {len(expired_ci)}건, 이미지 파기 대상 {len(leftover)}건")
    if dry_run:
        for row in expired_ci:
            click.echo(f"  CI  {row.verification_id}")
        for row in leftover:
            click.echo(f"  IMG {row.id}")
        click.echo("--dry-run이라 아무것도 지우지 않았다.")
        return

    delete_objects = not current_app.config.get("VULN_C10")
    if not delete_objects:
        click.echo("VULN_C10이 켜져 있다: DB 참조만 지우고 Storage 객체는 남긴다.")

    for row in expired_ci:
        row.ci = None
        row.ci_purged_at = now
        log_phone_event(row.verification_id, "CI_PURGED")
        log_access("system", "PURGED", target_id=str(row.verification_id), reason="CI 보관기한 경과")

    purged_images = 0
    for verification in leftover:
        purged_images += delete_verification_images(verification, delete_objects=delete_objects)
        log_access("system", "PURGED", target_id=str(verification.id), reason="종결 건 이미지 파기")

    db.session.commit()
    click.echo(f"CI {len(expired_ci)}건, 이미지 참조 {purged_images}건을 파기했다.")


@click.command("expire")
@with_appcontext
def expire_command() -> None:
    """20분이 지난 PENDING 건을 P03으로 종결하고 결과 웹훅을 보낸다."""
    from app.verify.termination import terminate

    now = now_utc()
    stale = db.session.scalars(
        db.select(Verification).where(
            Verification.status == "PENDING", Verification.expires_at <= now
        )
    ).all()

    click.echo(f"기준 시각 {kst_display(now)} · 만료된 진행 건 {len(stale)}건")
    for verification in stale:
        terminate(verification, "P03")
        click.echo(f"  P03 종결 {verification.id} (만료 {kst_display(verification.expires_at)})")
    click.echo(f"{len(stale)}건을 종결했다.")
