"""CI 모사값 계산과 X-01 대조."""

import pytest

from app.common.ci import CI_LENGTH, ci_matches, ci_mock

# 고정 입력 → 고정 출력 (A사·모의 통신사 구현을 맞추는 기준값)
KAT_KEY = "test-ci-key"
KAT_RRN = "9001011234568"
KAT_CI = "DMMReYuRkF7nVBqpgr7g5jRQErFwbz9FxB8VjOwsNnKnwuuDD06y2nFTFEzcuRl7pC56w03EcPF9w4o+ufbn3Q=="


def test_known_answer_and_length():
    assert ci_mock(KAT_RRN, KAT_KEY) == KAT_CI
    assert len(KAT_CI) == CI_LENGTH


def test_hyphenated_input_gives_same_ci():
    assert ci_mock("900101-1234568", KAT_KEY) == KAT_CI


def test_different_person_or_key_gives_different_ci():
    assert ci_mock("9001011234569", KAT_KEY) != KAT_CI
    assert ci_mock(KAT_RRN, "other-ci-key") != KAT_CI


def test_bad_rrn_raises():
    with pytest.raises(ValueError):
        ci_mock("90010112345", KAT_KEY)


def test_ci_matches_compares_safely():
    assert ci_matches(KAT_CI, ci_mock(KAT_RRN, KAT_KEY)) is True
    assert ci_matches(KAT_CI, ci_mock("9001011234569", KAT_KEY)) is False
    assert ci_matches(None, KAT_CI) is False  # CI 미수령 건은 절대 통과하지 않는다
    assert ci_matches(KAT_CI, None) is False
