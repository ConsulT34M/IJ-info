"""모의 통신사 가입자 명부 적재.

    python -m carrier.seed

A사 seed와 **같은 seed/people.json**을 써야 같은 인물의 CI가 일치한다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.common import secrets as secret_store
from app.common.crypto import aad, encrypt_str, hmac_sha256_hex, sha256_hex
from app.common.log_mask import mask_name, mask_phone
from app.common.rrn import normalize_rrn
from carrier import create_carrier_app
from carrier.models import CarrierClient, Subscriber, db

PEOPLE_FILE = Path(__file__).resolve().parents[1] / "seed" / "people.json"
CARRIER_CLIENT_ID = "ekyc-a"


def load_people(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"{path} 가 없다. 먼저 `python seed/make_people.py` 를 돌린다.")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["people"] if isinstance(data, dict) else data


def seed_subscribers(people: list[dict]) -> tuple[int, int]:
    """가입자 명부를 적재한다. 이미 있으면 갱신한다."""
    subscriber_key = secret_store.get_key("carrier/subscriber-key")
    rrn_key = secret_store.get_key("carrier/rrn-key")

    added = updated = 0
    for person in people:
        rrn = normalize_rrn(person["rrn"])
        if rrn is None:
            raise SystemExit(f"주민번호 형식이 아니다: person_no={person['person_no']}")

        subscriber_ref = f"SUB-{person['person_no']:04d}"
        values = {
            "phone_key": hmac_sha256_hex(subscriber_key, person["phone_number"]),
            "name_mac": hmac_sha256_hex(subscriber_key, person["name"]),
            "name_mask": mask_name(person["name"]),
            "rrn_ciphertext": encrypt_str(
                rrn_key, rrn, aad("subscriber", "rrn_ciphertext", subscriber_ref)
            ),
        }

        row = db.session.get(Subscriber, subscriber_ref)
        if row is None:
            db.session.add(Subscriber(subscriber_ref=subscriber_ref, **values))
            added += 1
        else:
            for key, value in values.items():
                setattr(row, key, value)
            updated += 1

    return added, updated


def seed_client() -> None:
    """A사 클라이언트 키를 등록한다(해시만 보관)."""
    digest = sha256_hex(secret_store.get_secret("ekyc/phone/carrier-client-key"))
    row = db.session.get(CarrierClient, CARRIER_CLIENT_ID)
    if row is None:
        db.session.add(CarrierClient(client_id=CARRIER_CLIENT_ID, key_digest=digest, status="ACTIVE"))
    else:
        row.key_digest = digest
        row.status = "ACTIVE"


def main() -> int:
    parser = argparse.ArgumentParser(description="모의 통신사 명부 적재")
    parser.add_argument("--people", type=Path, default=PEOPLE_FILE)
    args = parser.parse_args()

    secret_store.generate_dev_secrets()
    people = load_people(args.people)

    app = create_carrier_app()
    with app.app_context():
        db.create_all()
        added, updated = seed_subscribers(people)
        seed_client()
        db.session.commit()

    print(f"가입자 명부: 추가 {added}건, 갱신 {updated}건")
    print(f"사업자 키 등록: {CARRIER_CLIENT_ID}")
    for person in people:
        print(
            f"  SUB-{person['person_no']:04d} {mask_name(person['name'])} "
            f"{mask_phone(person['phone_number'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
