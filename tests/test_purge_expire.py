"""flask purge (CI·이미지 파기), flask expire (만료 건 종결)."""

from datetime import timedelta

import pytest

from app.cli import expire_command, purge_command
from app.common.storage import get_storage
from app.common.timeutil import now_utc
from app.models import AccessLog, IdDocument, PhoneEvent, PhoneVerification, Verification, db


@pytest.fixture
def person(seeded):
    return seeded[0]


@pytest.fixture
def finished_case(flow, carrier_backend, sent_webhooks, person):
    """성공 완주한 건(CI 보관 중, 이미지는 판정 때 파기됨)."""
    flow.to_face(person)
    assert flow.upload_face().status_code == 302
    return flow.verification_id


def test_ci_is_purged_seven_days_after_delivery(runner, finished_case, app):
    phone = db.session.get(PhoneVerification, finished_case)
    assert phone.ci and phone.ci_first_delivered_at is not None

    phone.ci_first_delivered_at = now_utc() - timedelta(days=7, seconds=1)
    db.session.commit()

    result = runner.invoke(purge_command)
    assert result.exit_code == 0, result.output
    assert "CI 파기 대상 1건" in result.output

    db.session.expire_all()
    phone = db.session.get(PhoneVerification, finished_case)
    assert phone.ci is None and phone.ci_purged_at is not None

    kinds = [row.event_kind for row in db.session.scalars(
        db.select(PhoneEvent).filter_by(verification_id=finished_case)
    ).all()]
    assert "CI_PURGED" in kinds

    log = db.session.scalars(db.select(AccessLog).filter_by(action="PURGED")).first()
    assert log.actor == "system" and log.target_id == str(finished_case)
    assert "보관기한" in log.reason


def test_ci_is_kept_before_the_retention_period(runner, finished_case):
    phone = db.session.get(PhoneVerification, finished_case)
    phone.ci_first_delivered_at = now_utc() - timedelta(days=6, hours=23)
    db.session.commit()

    result = runner.invoke(purge_command)
    assert "CI 파기 대상 0건" in result.output
    db.session.expire_all()
    assert db.session.get(PhoneVerification, finished_case).ci is not None


def test_undelivered_ci_is_purged_after_thirty_days(runner, finished_case):
    verification = db.session.get(Verification, finished_case)
    phone = db.session.get(PhoneVerification, finished_case)
    phone.ci_first_delivered_at = None  # 웹훅 유실 + IA-12 조회 없음
    verification.completed_at = now_utc() - timedelta(days=30, seconds=1)
    db.session.commit()

    assert runner.invoke(purge_command).exit_code == 0
    db.session.expire_all()
    assert db.session.get(PhoneVerification, finished_case).ci is None

    phone = db.session.get(PhoneVerification, finished_case)
    assert phone.ci_purged_at is not None


def test_undelivered_ci_is_kept_before_thirty_days(runner, finished_case):
    verification = db.session.get(Verification, finished_case)
    phone = db.session.get(PhoneVerification, finished_case)
    phone.ci_first_delivered_at = None
    verification.completed_at = now_utc() - timedelta(days=29)
    db.session.commit()

    runner.invoke(purge_command)
    db.session.expire_all()
    assert db.session.get(PhoneVerification, finished_case).ci is not None


def test_leftover_images_of_finished_cases_are_purged(runner, flow, carrier_backend, person):
    """판정 전에 종결된 흔적이 있어도 파기 배치가 치운다."""
    flow.to_id_card(person)
    flow.upload_id_card()
    verification = db.session.get(Verification, flow.verification_id)
    # terminate를 거치지 않고 종결된 상태를 만든다(과거 데이터·중단된 배치를 가정)
    verification.status = "FAILED"
    verification.reason_code = "E06"
    verification.completed_at = now_utc()
    db.session.commit()

    key = db.session.get(IdDocument, flow.verification_id).s3_key
    assert key and get_storage().exists(key)

    result = runner.invoke(purge_command)
    assert "이미지 파기 대상 1건" in result.output

    db.session.expire_all()
    document = db.session.get(IdDocument, flow.verification_id)
    assert document.s3_key is None and document.deleted_at is not None
    assert get_storage().exists(key) is False

    log = db.session.scalars(
        db.select(AccessLog).filter_by(action="PURGED", target_id=str(flow.verification_id))
    ).one()
    assert "이미지" in log.reason


def test_images_of_pending_cases_are_left_alone(runner, flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    key = db.session.get(IdDocument, flow.verification_id).s3_key

    result = runner.invoke(purge_command)
    assert "이미지 파기 대상 0건" in result.output
    db.session.expire_all()
    assert db.session.get(IdDocument, flow.verification_id).s3_key == key
    assert get_storage().exists(key)


def test_dry_run_changes_nothing(runner, finished_case):
    phone = db.session.get(PhoneVerification, finished_case)
    phone.ci_first_delivered_at = now_utc() - timedelta(days=8)
    db.session.commit()

    result = runner.invoke(purge_command, ["--dry-run"])
    assert "아무것도 지우지 않았다" in result.output
    db.session.expire_all()
    assert db.session.get(PhoneVerification, finished_case).ci is not None
    assert db.session.scalars(db.select(AccessLog).filter_by(action="PURGED")).all() == []


def test_expire_closes_stale_pending_cases(runner, flow, carrier_backend, sent_webhooks, person):
    flow.to_phone()
    verification = db.session.get(Verification, flow.verification_id)
    verification.created_at = now_utc() - timedelta(minutes=30)
    verification.expires_at = now_utc() - timedelta(minutes=10)
    db.session.commit()

    result = runner.invoke(expire_command)
    assert result.exit_code == 0, result.output
    assert "1건을 종결했다" in result.output
    assert "+09:00" in result.output  # KST 표시(D73)

    db.session.expire_all()
    verification = db.session.get(Verification, flow.verification_id)
    assert verification.status == "EXPIRED" and verification.reason_code == "P03"
    assert verification.stage == "DONE"

    assert len(sent_webhooks) == 1
    assert sent_webhooks[0]["payload"]["reason_code"] == "P03"


def test_expire_leaves_live_cases(runner, flow, carrier_backend, sent_webhooks, person):
    flow.to_phone()
    result = runner.invoke(expire_command)
    assert "0건을 종결했다" in result.output
    db.session.expire_all()
    assert db.session.get(Verification, flow.verification_id).status == "PENDING"
    assert sent_webhooks == []


def test_expire_is_idempotent(runner, flow, carrier_backend, sent_webhooks, person):
    flow.to_phone()
    verification = db.session.get(Verification, flow.verification_id)
    verification.created_at = now_utc() - timedelta(minutes=30)
    verification.expires_at = now_utc() - timedelta(minutes=10)
    db.session.commit()

    runner.invoke(expire_command)
    runner.invoke(expire_command)
    assert len(sent_webhooks) == 1  # 웹훅은 한 번만
