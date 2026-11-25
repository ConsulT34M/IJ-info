"""데이터 모델 13개와 CHECK 제약."""

import uuid
from datetime import date, timedelta

import pytest
import sqlalchemy as sa

from app.common.crypto import aad, decrypt_str, encrypt_str
from app.common import secrets as secrets_mod
from app.common.timeutil import now_utc
from app.models import (
    REASON_CODES,
    AccessLog,
    Admin,
    Consent,
    FaceCheck,
    IdDocument,
    MockMoisRegistry,
    PhoneEvent,
    PhoneOtp,
    PhoneVerification,
    TestPhone,
    Verification,
    db,
)

EXPECTED_TABLES = {
    "clients",
    "verifications",
    "consents",
    "callbacks",
    "admins",
    "access_logs",
    "phone_verifications",
    "phone_otps",
    "test_phones",
    "phone_events",
    "id_documents",
    "face_checks",
    "mock_mois_registry",
}


def _expect_integrity_error(row):
    db.session.add(row)
    with pytest.raises(sa.exc.IntegrityError):
        db.session.commit()
    db.session.rollback()


def _expect_integrity_error_on_commit():
    with pytest.raises(sa.exc.IntegrityError):
        db.session.commit()
    db.session.rollback()


# 11장에 없는 표. 회사 홈페이지(공개 화면) 전용이고 개인정보 흐름에 들어가지 않는다(D90).
SITE_TABLES = {"site_inquiries", "site_documents"}


def test_thirteen_tables_exist(app):
    """명세 11장의 13개 표가 그대로 있는지 본다."""
    assert len(EXPECTED_TABLES) == 13
    assert EXPECTED_TABLES <= set(db.metadata.tables)
    inspector = sa.inspect(db.engine)
    assert EXPECTED_TABLES <= set(inspector.get_table_names())


def test_no_table_sneaks_in_outside_the_spec(app):
    """11장 13개 + 홈페이지 2개가 전부여야 한다. 모르는 표가 생기면 알아차린다."""
    assert set(db.metadata.tables) == EXPECTED_TABLES | SITE_TABLES


def test_reason_code_list_matches_chapter_ten():
    assert set(REASON_CODES) == {
        "OK", "P01", "P02", "P03", "P04", "P05",
        "E01", "E02", "E03", "E04", "E05", "E06", "X01",
    }


def test_new_verification_starts_at_consent_stage(make_verification):
    row = make_verification()
    assert row.stage == "CONSENT"
    assert row.status == "PENDING"
    assert row.reason_code is None
    assert row.last_error_code is None
    assert row.face_attempts == 0
    assert row.is_finished is False


@pytest.mark.parametrize("column,value", [("stage", "PHONE_OTP"), ("status", "DONE")])
def test_unknown_stage_or_status_is_rejected(make_verification, column, value):
    row = make_verification()
    setattr(row, column, value)
    _expect_integrity_error_on_commit()


def test_face_attempts_cannot_exceed_three(make_verification):
    row = make_verification()
    row.face_attempts = 3
    db.session.commit()
    row.face_attempts = 4
    _expect_integrity_error_on_commit()


def test_expires_at_must_be_after_created_at(make_verification):
    created = now_utc()
    with pytest.raises(sa.exc.IntegrityError):
        make_verification(created_at=created, expires_at=created - timedelta(seconds=1))
    db.session.rollback()


def test_pending_verification_cannot_carry_reason_code(make_verification):
    row = make_verification()
    row.reason_code = "OK"
    _expect_integrity_error_on_commit()


def test_finished_verification_must_carry_reason_code(make_verification):
    row = make_verification()
    row.status = "FAILED"
    _expect_integrity_error_on_commit()


def test_last_error_code_is_allowed_while_pending(make_verification):
    """D8: 진행 중 실패 코드는 last_error_code에만 남는다."""
    row = make_verification()
    row.last_error_code = "E02"
    db.session.commit()
    assert row.status == "PENDING" and row.reason_code is None

    row.status = "FAILED"
    row.reason_code = "E06"
    row.completed_at = now_utc()
    db.session.commit()
    assert row.last_error_code == "E02" and row.reason_code == "E06"


def test_unknown_error_codes_are_rejected(make_verification):
    row = make_verification()
    row.last_error_code = "E99"
    _expect_integrity_error_on_commit()


def test_token_hash_is_unique(make_verification):
    make_verification(token_hash="a" * 64)
    with pytest.raises(sa.exc.IntegrityError):
        make_verification(token_hash="a" * 64)
    db.session.rollback()


def test_consent_is_recorded_once_per_type(make_verification):
    row = make_verification()
    db.session.add(Consent(verification_id=row.id, type="collect", version="v1.0", ip="127.0.0.1"))
    db.session.commit()
    _expect_integrity_error(
        Consent(verification_id=row.id, type="collect", version="v1.0", ip="127.0.0.1")
    )
    _expect_integrity_error(
        Consent(verification_id=row.id, type="marketing", version="v1.0", ip="127.0.0.1")
    )


def test_image_view_and_download_require_a_reason(app):
    db.session.add(
        AccessLog(actor="admin", actor_id="admin1", action="HISTORY_VIEW", ip="127.0.0.1")
    )
    db.session.commit()

    _expect_integrity_error(
        AccessLog(actor="admin", actor_id="admin1", action="IMAGE_VIEW", ip="127.0.0.1")
    )
    _expect_integrity_error(
        AccessLog(
            actor="admin", actor_id="admin1", action="HISTORY_DOWNLOAD", reason="   ", ip="127.0.0.1"
        )
    )

    db.session.add(
        AccessLog(
            actor="admin",
            actor_id="admin1",
            action="IMAGE_VIEW",
            target_id="v-1",
            reason="고객 민원 확인",
            ip="127.0.0.1",
        )
    )
    db.session.commit()


def test_unknown_actor_or_action_is_rejected(app):
    _expect_integrity_error(AccessLog(actor="hacker", action="HISTORY_VIEW"))
    _expect_integrity_error(AccessLog(actor="admin", action="DROP_TABLE"))


def test_masked_values_only_on_identity_match(make_verification):
    row = make_verification()
    db.session.add(
        PhoneEvent(
            verification_id=row.id,
            event_kind="IDENTITY_MATCH",
            name_mask="홍*동",
            phone_mask="010-****-1234",
        )
    )
    db.session.commit()

    _expect_integrity_error(
        PhoneEvent(verification_id=row.id, event_kind="OTP_ISSUED", phone_mask="010-****-1234")
    )
    _expect_integrity_error(
        PhoneEvent(verification_id=row.id, event_kind="CI_ISSUED", name_mask="홍*동")
    )
    _expect_integrity_error(PhoneEvent(verification_id=row.id, event_kind="SOMETHING"))
    _expect_integrity_error(
        PhoneEvent(verification_id=row.id, event_kind="FAILED", result_code="Z99")
    )


def test_phone_verification_limits(make_verification):
    row = make_verification()
    phone = PhoneVerification(verification_id=row.id)
    db.session.add(phone)
    db.session.commit()
    assert phone.status == "PENDING"
    assert phone.ci is None and phone.match_token_enc is None

    phone.ci = "x" * 87
    _expect_integrity_error_on_commit()

    phone.ci = "x" * 88
    db.session.commit()

    phone.match_attempts = 4
    _expect_integrity_error_on_commit()

    phone.otp_attempts = 4
    _expect_integrity_error_on_commit()

    phone.status = "OK"
    _expect_integrity_error_on_commit()


def test_face_check_similarity_range(make_verification):
    row = make_verification()
    db.session.add(FaceCheck(verification_id=row.id, face_count=1, similarity=95, matched=True))
    db.session.commit()
    _expect_integrity_error(FaceCheck(verification_id=row.id, similarity=101))
    _expect_integrity_error(FaceCheck(verification_id=row.id, face_count=-1))


def test_admin_role_is_limited(app):
    _expect_integrity_error(
        Admin(
            login_id="root",
            password_hash="x",
            otp_secret=b"x",
            role="superuser",
            allowed_ips=["127.0.0.1"],
        )
    )


def test_mois_registry_is_one_row_per_person(app):
    db.session.add(
        MockMoisRegistry(name="홍길동", rrn_hash="a" * 64, issue_date=date(2015, 3, 2), status="정상")
    )
    db.session.commit()
    _expect_integrity_error(
        MockMoisRegistry(name="홍길동", rrn_hash="a" * 64, issue_date=date(2015, 3, 2), status="분실")
    )
    _expect_integrity_error(
        MockMoisRegistry(name="홍길동", rrn_hash="b" * 64, issue_date=date(2015, 3, 2), status="정지")
    )


def test_foreign_keys_are_enforced(app):
    _expect_integrity_error(
        Verification(
            client_id=uuid.uuid4(),
            client_user_ref="ghost",
            return_url="http://127.0.0.1:9000/done",
            expires_at=now_utc() + timedelta(minutes=20),
        )
    )


def test_rrn_is_stored_encrypted_and_bound_to_the_row(make_verification):
    """D17: 암호문은 verification_id에 묶인다. 다른 건으로 옮기면 복호화가 실패한다."""
    from app.common.crypto import DecryptError

    row = make_verification()
    other = make_verification(client_user_ref="user-0002")
    key = secrets_mod.get_key("ekyc/rrn-key")

    document = IdDocument(
        verification_id=row.id,
        name="홍길동",
        rrn_enc=encrypt_str(key, "9001011234568", aad("id_documents", "rrn_enc", row.id)),
        birth_date=date(1990, 1, 1),
        issue_date=date(2015, 3, 2),
    )
    db.session.add(document)
    db.session.commit()

    assert b"9001011234568" not in document.rrn_enc
    assert decrypt_str(key, document.rrn_enc, aad("id_documents", "rrn_enc", row.id)) == "9001011234568"
    with pytest.raises(DecryptError):
        decrypt_str(key, document.rrn_enc, aad("id_documents", "rrn_enc", other.id))


def test_otp_row_keeps_mac_not_plaintext(make_verification):
    row = make_verification()
    db.session.add(
        PhoneOtp(
            verification_id=row.id,
            phone_key="b" * 64,
            issue_no=1,
            code_expires_at=now_utc() + timedelta(minutes=3),
            code_mac="c" * 64,
        )
    )
    db.session.commit()
    stored = db.session.get(PhoneOtp, row.id)
    assert stored.issue_no == 1 and stored.inbox_ciphertext is None
    stored.issue_no = 0
    _expect_integrity_error_on_commit()


def test_test_phone_keeps_no_plaintext_number(app):
    db.session.add(
        TestPhone(phone_key="d" * 64, phone_mask="010-****-1234", inbox_key_hash="e" * 64)
    )
    db.session.commit()
    row = db.session.get(TestPhone, "d" * 64)
    assert row.phone_mask == "010-****-1234"
    assert row.next_issue_at is None
    assert not hasattr(row, "phone_number")
