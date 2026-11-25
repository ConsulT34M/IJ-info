"""가상 인물 10명 생성 → seed/people.json (고정 시드, 커밋 금지).

실제 개인정보는 쓰지 않는다. 성명은 Faker ko_KR, 주민번호는 체크섬만 맞춘 가상 값,
휴대폰번호는 가짜 번호다. A사 seed와 모의 통신사 seed가 같은 people.json을 써야
같은 인물의 ci_mock이 일치한다.

    python seed/make_people.py [--out seed/people.json] [--seed 20261126]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from faker import Faker  # noqa: E402

from app.common.log_mask import mask_name, mask_phone, mask_rrn  # noqa: E402
from app.common.rrn import build_rrn, validate_issue_date, validate_rrn  # noqa: E402

DEFAULT_SEED = 20261129
PEOPLE_COUNT = 10
DEFAULT_OUT = Path(__file__).resolve().parent / "people.json"

# 진위확인 대장에서 '분실'로 등록할 인물 (E03 테스트용)
LOST_ID_PERSON_NO = 9

STATUS_NORMAL = "정상"
STATUS_LOST = "분실"


def _birth_date(rng: random.Random) -> date:
    """1965~2006년 사이 생년월일."""
    start = date(1965, 1, 1)
    end = date(2006, 12, 31)
    return start + timedelta(days=rng.randrange((end - start).days + 1))


def _gender_digit(rng: random.Random, birth: date) -> str:
    """출생 세기에 맞는 성별 자리(1·2 = 1900년대, 3·4 = 2000년대)."""
    return rng.choice(["1", "2"]) if birth.year < 2000 else rng.choice(["3", "4"])


def _issue_date(rng: random.Random, birth: date, today: date) -> date:
    """만 17세 이후 ~ 어제 사이의 발급일자."""
    earliest = birth + timedelta(days=17 * 365)
    latest = today - timedelta(days=1)
    span = (latest - earliest).days
    return earliest + timedelta(days=rng.randrange(span + 1))


def make_people(seed: int = DEFAULT_SEED, count: int = PEOPLE_COUNT, today: date | None = None) -> list[dict]:
    """고정 시드로 가상 인물 목록을 만든다. 같은 시드면 항상 같은 결과다."""
    today = today or date(2026, 11, 26)
    rng = random.Random(seed)
    faker = Faker("ko_KR")
    Faker.seed(seed)
    faker.unique.clear()

    people: list[dict] = []
    used_phones: set[str] = set()
    used_rrns: set[str] = set()

    for person_no in range(1, count + 1):
        birth = _birth_date(rng)
        gender = _gender_digit(rng, birth)
        while True:
            rrn = build_rrn(birth, gender, f"{rng.randrange(100000):05d}")
            if rrn not in used_rrns:
                used_rrns.add(rrn)
                break
        while True:
            phone = f"010{rng.randrange(1000, 10000)}{rng.randrange(1000, 10000)}"
            if phone not in used_phones:
                used_phones.add(phone)
                break

        issued = _issue_date(rng, birth, today)
        person = {
            "person_no": person_no,
            "name": faker.unique.name_male() if gender in ("1", "3") else faker.unique.name_female(),
            "rrn": rrn,
            "birth_date": birth.isoformat(),
            "issue_date": issued.isoformat(),
            "phone_number": phone,
            "inbox_key": f"{rng.randrange(16**12):012x}",
            "mois_status": STATUS_LOST if person_no == LOST_ID_PERSON_NO else STATUS_NORMAL,
        }

        check = validate_rrn(person["rrn"])
        assert check.ok, (person_no, check.error)
        assert check.birth_date == birth
        issue_check = validate_issue_date(person["issue_date"], birth, today)
        assert issue_check.ok, (person_no, issue_check.error)
        people.append(person)

    return people


def main() -> int:
    parser = argparse.ArgumentParser(description="가상 인물 10명 생성")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    people = make_people(seed=args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps({"seed": args.seed, "people": people}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    args.out.chmod(0o600)

    print(f"가상 인물 {len(people)}명 → {args.out}")
    print(f"{'번호':<4} {'성명':<6} {'주민번호':<16} {'휴대폰':<15} 진위확인")
    for person in people:
        print(
            f"{person['person_no']:<5} {mask_name(person['name']):<7} "
            f"{mask_rrn(person['rrn']):<16} {mask_phone(person['phone_number']):<15} "
            f"{person['mois_status']}"
        )
    print("수신함 키와 원본 값은 people.json에서 본다(gitignore).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
