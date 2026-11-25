"""가상 인물 시드: 고정 시드 재현성, 주민번호 유효성, CI 일치."""

from datetime import date

from app.common import secrets as secrets_mod
from app.common.ci import ci_matches, ci_mock
from app.common.rrn import validate_issue_date, validate_rrn
from seed.make_people import LOST_ID_PERSON_NO, PEOPLE_COUNT, STATUS_LOST, STATUS_NORMAL, make_people


def test_fixed_seed_is_reproducible():
    assert make_people() == make_people()
    assert make_people(seed=1) != make_people(seed=2)


def test_ten_people_numbered_one_to_ten(people):
    assert len(people) == PEOPLE_COUNT == 10
    assert [p["person_no"] for p in people] == list(range(1, 11))


def test_person_nine_is_registered_as_lost(people):
    by_no = {p["person_no"]: p for p in people}
    assert by_no[LOST_ID_PERSON_NO]["mois_status"] == STATUS_LOST
    assert all(p["mois_status"] == STATUS_NORMAL for p in people if p["person_no"] != LOST_ID_PERSON_NO)


def test_every_rrn_passes_the_checker(people):
    for person in people:
        check = validate_rrn(person["rrn"])
        assert check.ok, (person["person_no"], check.error)
        assert check.birth_date == date.fromisoformat(person["birth_date"])


def test_every_issue_date_passes_the_checker(people):
    for person in people:
        check = validate_issue_date(
            person["issue_date"], date.fromisoformat(person["birth_date"]), today=date(2026, 11, 26)
        )
        assert check.ok, (person["person_no"], check.error)


def test_phone_numbers_look_fake_and_are_unique(people):
    phones = [p["phone_number"] for p in people]
    assert len(set(phones)) == len(phones)
    assert all(phone.startswith("010") and len(phone) == 11 and phone.isdigit() for phone in phones)


def test_names_rrns_and_inbox_keys_are_unique(people):
    for field in ("name", "rrn", "inbox_key"):
        values = [p[field] for p in people]
        assert len(set(values)) == len(values), field


def test_both_centuries_and_genders_are_covered(people):
    digits = {p["rrn"][6] for p in people}
    assert digits & {"1", "2"} and digits & {"3", "4"}


def test_same_person_gets_same_ci_on_both_sides(dev_secrets, people):
    """A사가 주민번호로 계산한 CI = 모의 통신사가 발급한 CI (X-01 통과 조건)."""
    ekyc_key = secrets_mod.get_key("ekyc/ci-key")
    carrier_key = secrets_mod.get_key("carrier/ci-key")
    for person in people:
        assert ci_matches(ci_mock(person["rrn"], ekyc_key), ci_mock(person["rrn"], carrier_key))


def test_different_person_gets_different_ci(dev_secrets, people):
    """X-01 불일치(휴대폰 명의자 ≠ 신분증 명의자)가 실제로 잡힌다."""
    key = secrets_mod.get_key("ekyc/ci-key")
    cis = [ci_mock(person["rrn"], key) for person in people]
    assert len(set(cis)) == len(cis)
    assert not ci_matches(cis[0], cis[1])
