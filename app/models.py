"""A사 PostgreSQL 데이터 모델 (13개 테이블).

- 시각은 naive UTC로 저장한다(D23). 화면·웹훅에서 KST로 바꾼다.
- 주민번호·TOTP 시크릿·대조 토큰·수신함 인증번호는 암호문(bytea)으로만 넣는다.
- 휴대폰번호 원문은 어디에도 저장하지 않는다(phone_key HMAC + 마스킹값만).
- access_logs·phone_events는 앱 코드에서 INSERT만 한다.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal

import sqlalchemy as sa
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.common.timeutil import now_utc


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)

# --- 코드 목록 (CHECK 제약으로 DB에도 박는다) ---

STAGES = ("CONSENT", "PHONE", "ID_CARD", "ID_CONFIRM", "FACE", "DONE")
STATUSES = ("PENDING", "SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED")
REASON_CODES = (
    "OK",
    "P01", "P02", "P03", "P04", "P05",
    "E01", "E02", "E03", "E04", "E05", "E06",
    "X01",
)
CONSENT_TYPES = ("collect", "uid", "carrier_terms", "biometric")
PHONE_STATUSES = ("PENDING", "PASSED", "FAILED")
ADMIN_ROLES = ("admin", "auditor")
ACTORS = ("admin", "client", "system")
ACCESS_ACTIONS = (
    "REQUEST_RECEIVED",
    "RESULT_QUERIED",
    "CALLBACK_SENT",
    "CI_MISMATCH",
    "HISTORY_VIEW",
    "HISTORY_DOWNLOAD",
    "IMAGE_VIEW",
    "ROLE_CHANGE",
    "PURGED",
)
# 사유 입력이 필수인 행위 (15장)
ACTIONS_REQUIRING_REASON = ("HISTORY_DOWNLOAD", "IMAGE_VIEW")
PHONE_EVENT_KINDS = (
    "IDENTITY_MATCH",
    "OTP_ISSUED",
    "OTP_REISSUED",
    "OTP_VERIFIED",
    "CI_ISSUED",
    "CI_DELIVERED",
    "CI_PURGED",
    "FAILED",
)
CLIENT_STATUSES = ("ACTIVE", "SUSPENDED")
MOIS_STATUSES = ("정상", "분실")

CI_LENGTH = 88


# SQLite는 BIGINT PK 자동증가를 지원하지 않는다(INTEGER PRIMARY KEY만). 방언별로 바꿔 준다.
BIG_INT_PK = sa.BigInteger().with_variant(sa.Integer, "sqlite")


def _in_list(column: str, values: tuple[str, ...]) -> str:
    """CHECK 제약용 IN 절을 만든다."""
    return f"{column} IN (" + ", ".join(f"'{value}'" for value in values) + ")"


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class Client(db.Model):
    """위탁사(거래소). API Key는 해시로만, HMAC Secret은 시크릿 저장소 참조로만 둔다."""

    __tablename__ = "clients"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False, unique=True)
    api_key_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    hmac_secret_ref: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    callback_url: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    allowed_ips: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(sa.String(10), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)

    verifications: Mapped[list["Verification"]] = relationship(back_populates="client")

    __table_args__ = (
        sa.CheckConstraint(_in_list("status", CLIENT_STATUSES), name="ck_clients_status"),
    )


class Verification(db.Model):
    """인증 건. 하나의 인증 흐름 전체가 이 행 하나에 묶인다."""

    __tablename__ = "verifications"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    client_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True
    )
    client_user_ref: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    # 인증창 토큰: 해시만 보관하고 1회 사용 시 token_used_at을 원자적으로 기록한다
    token_hash: Mapped[str | None] = mapped_column(sa.String(64), unique=True)
    token_used_at: Mapped[datetime | None] = mapped_column(sa.DateTime)
    # D7: 인증창 세션 식별값. 토큰을 재발급하면 이 값도 바뀌어 기존 탭이 무효가 된다
    entry_nonce: Mapped[str | None] = mapped_column(sa.String(64))
    stage: Mapped[str] = mapped_column(sa.String(12), nullable=False, default="CONSENT")
    status: Mapped[str] = mapped_column(sa.String(12), nullable=False, default="PENDING")
    reason_code: Mapped[str | None] = mapped_column(sa.String(4))
    # D8: 진행 중 실패 코드(P01, E01~E05). reason_code는 종결 시에만 채운다
    last_error_code: Mapped[str | None] = mapped_column(sa.String(4))
    face_attempts: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    return_url: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime)

    client: Mapped["Client"] = relationship(back_populates="verifications")
    phone: Mapped["PhoneVerification | None"] = relationship(
        back_populates="verification", uselist=False
    )
    otp: Mapped["PhoneOtp | None"] = relationship(back_populates="verification", uselist=False)
    id_document: Mapped["IdDocument | None"] = relationship(
        back_populates="verification", uselist=False
    )
    consents: Mapped[list["Consent"]] = relationship(back_populates="verification")
    events: Mapped[list["PhoneEvent"]] = relationship(back_populates="verification")
    face_checks: Mapped[list["FaceCheck"]] = relationship(back_populates="verification")
    callbacks: Mapped[list["Callback"]] = relationship(back_populates="verification")

    __table_args__ = (
        sa.CheckConstraint(_in_list("stage", STAGES), name="ck_verifications_stage"),
        sa.CheckConstraint(_in_list("status", STATUSES), name="ck_verifications_status"),
        sa.CheckConstraint(
            f"reason_code IS NULL OR {_in_list('reason_code', REASON_CODES)}",
            name="ck_verifications_reason_code",
        ),
        sa.CheckConstraint(
            f"last_error_code IS NULL OR {_in_list('last_error_code', REASON_CODES)}",
            name="ck_verifications_last_error_code",
        ),
        # 진행 중에는 reason_code가 없고, 종결되면 반드시 있다
        sa.CheckConstraint(
            "(status = 'PENDING' AND reason_code IS NULL)"
            " OR (status <> 'PENDING' AND reason_code IS NOT NULL)",
            name="ck_verifications_reason_code_when_finished",
        ),
        sa.CheckConstraint(
            "face_attempts BETWEEN 0 AND 3", name="ck_verifications_face_attempts"
        ),
        sa.CheckConstraint("expires_at > created_at", name="ck_verifications_expires_at"),
        sa.Index("ix_verifications_client_user_ref", "client_id", "client_user_ref", "status"),
    )

    @property
    def is_finished(self) -> bool:
        """종결된 건은 다시 열지 않는다."""
        return self.status != "PENDING"


class Consent(db.Model):
    """동의 4종. 종류별로 한 번만 기록한다."""

    __tablename__ = "consents"

    id: Mapped[int] = mapped_column(BIG_INT_PK, primary_key=True, autoincrement=True)
    verification_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("verifications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(sa.String(20), nullable=False)
    version: Mapped[str] = mapped_column(sa.String(20), nullable=False)
    agreed_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)
    ip: Mapped[str] = mapped_column(sa.String(45), nullable=False)

    verification: Mapped["Verification"] = relationship(back_populates="consents")

    __table_args__ = (
        sa.CheckConstraint(_in_list("type", CONSENT_TYPES), name="ck_consents_type"),
        sa.UniqueConstraint("verification_id", "type", name="uq_consents_verification_type"),
    )


class Callback(db.Model):
    """결과 웹훅(IA-11) 전송 기록. 본문은 해시만 남긴다."""

    __tablename__ = "callbacks"

    id: Mapped[int] = mapped_column(BIG_INT_PK, primary_key=True, autoincrement=True)
    verification_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("verifications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    payload_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    http_status: Mapped[int | None] = mapped_column(sa.Integer)
    retry_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    sent_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)

    verification: Mapped["Verification"] = relationship(back_populates="callbacks")


class Admin(db.Model):
    """관리자 콘솔 계정. TOTP 시크릿은 암호문으로만 보관한다."""

    __tablename__ = "admins"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=_uuid)
    login_id: Mapped[str] = mapped_column(sa.String(50), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    otp_secret: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    role: Mapped[str] = mapped_column(sa.String(10), nullable=False)
    allowed_ips: Mapped[list] = mapped_column(sa.JSON, nullable=False, default=list)
    failed_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(sa.DateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)

    __table_args__ = (
        sa.CheckConstraint(_in_list("role", ADMIN_ROLES), name="ck_admins_role"),
        sa.CheckConstraint("failed_count >= 0", name="ck_admins_failed_count"),
    )


class AccessLog(db.Model):
    """접속·열람 기록. INSERT만 한다(UPDATE/DELETE 없음)."""

    __tablename__ = "access_logs"

    id: Mapped[int] = mapped_column(BIG_INT_PK, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(sa.String(10), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(sa.String(100))
    action: Mapped[str] = mapped_column(sa.String(30), nullable=False)
    target_id: Mapped[str | None] = mapped_column(sa.String(100))
    reason: Mapped[str | None] = mapped_column(sa.Text)
    ip: Mapped[str | None] = mapped_column(sa.String(45))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime, nullable=False, default=now_utc, index=True
    )

    __table_args__ = (
        sa.CheckConstraint(_in_list("actor", ACTORS), name="ck_access_logs_actor"),
        sa.CheckConstraint(_in_list("action", ACCESS_ACTIONS), name="ck_access_logs_action"),
        # 이력 다운로드·이미지 열람은 사유가 반드시 있어야 한다
        sa.CheckConstraint(
            f"NOT {_in_list('action', ACTIONS_REQUIRING_REASON)}"
            " OR (reason IS NOT NULL AND length(trim(reason)) > 0)",
            name="ck_access_logs_reason_required",
        ),
    )


class PhoneVerification(db.Model):
    """휴대폰 본인확인 결과와 CI 보관 상태."""

    __tablename__ = "phone_verifications"

    verification_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("verifications.id", ondelete="CASCADE"), primary_key=True
    )
    status: Mapped[str] = mapped_column(sa.String(10), nullable=False, default="PENDING")
    match_attempts: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    otp_attempts: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    # 대조 토큰은 암호문으로만. CI 발급·종결 시 NULL로 지운다
    match_token_enc: Mapped[bytes | None] = mapped_column(sa.LargeBinary)
    ci: Mapped[str | None] = mapped_column(sa.String(CI_LENGTH))
    ci_first_delivered_at: Mapped[datetime | None] = mapped_column(sa.DateTime)
    ci_purged_at: Mapped[datetime | None] = mapped_column(sa.DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)

    verification: Mapped["Verification"] = relationship(back_populates="phone")

    __table_args__ = (
        sa.CheckConstraint(_in_list("status", PHONE_STATUSES), name="ck_phone_verifications_status"),
        sa.CheckConstraint(
            "match_attempts BETWEEN 0 AND 3", name="ck_phone_verifications_match_attempts"
        ),
        sa.CheckConstraint(
            "otp_attempts BETWEEN 0 AND 3", name="ck_phone_verifications_otp_attempts"
        ),
        sa.CheckConstraint(
            f"ci IS NULL OR length(ci) = {CI_LENGTH}", name="ck_phone_verifications_ci_length"
        ),
    )


class PhoneOtp(db.Model):
    """발송된 인증번호 한 건. 재발송은 같은 행을 갱신하고 issue_no를 올린다(D6)."""

    __tablename__ = "phone_otps"

    verification_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("verifications.id", ondelete="CASCADE"), primary_key=True
    )
    phone_key: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    issue_no: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    issued_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)
    code_expires_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False)
    # 검증은 code_mac으로만 한다. inbox_ciphertext는 테스트 수신함 전용이고 사용·만료 즉시 지운다
    code_mac: Mapped[str | None] = mapped_column(sa.String(64))
    inbox_ciphertext: Mapped[bytes | None] = mapped_column(sa.LargeBinary)

    verification: Mapped["Verification"] = relationship(back_populates="otp")

    __table_args__ = (sa.CheckConstraint("issue_no >= 1", name="ck_phone_otps_issue_no"),)


class TestPhone(db.Model):
    """테스트 문자 수신함 (실습 전용). 번호 원문은 저장하지 않는다."""

    __test__ = False  # 이름이 Test로 시작해 pytest가 수집하려 드는 것을 막는다
    __tablename__ = "test_phones"

    phone_key: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    phone_mask: Mapped[str] = mapped_column(sa.String(20), nullable=False)
    inbox_key_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    # D11: 번호 단위 재발송 제한(60초)
    next_issue_at: Mapped[datetime | None] = mapped_column(sa.DateTime)


class PhoneEvent(db.Model):
    """휴대폰 단계 이력. INSERT만 한다."""

    __tablename__ = "phone_events"

    id: Mapped[int] = mapped_column(BIG_INT_PK, primary_key=True, autoincrement=True)
    verification_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("verifications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_kind: Mapped[str] = mapped_column(sa.String(20), nullable=False)
    result_code: Mapped[str | None] = mapped_column(sa.String(4))
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)
    name_mask: Mapped[str | None] = mapped_column(sa.String(20))
    phone_mask: Mapped[str | None] = mapped_column(sa.String(20))

    verification: Mapped["Verification"] = relationship(back_populates="events")

    __table_args__ = (
        sa.CheckConstraint(_in_list("event_kind", PHONE_EVENT_KINDS), name="ck_phone_events_kind"),
        sa.CheckConstraint(
            f"result_code IS NULL OR {_in_list('result_code', REASON_CODES)}",
            name="ck_phone_events_result_code",
        ),
        # 성명·번호 마스킹값은 IDENTITY_MATCH에서만 남긴다
        sa.CheckConstraint(
            "event_kind = 'IDENTITY_MATCH' OR (name_mask IS NULL AND phone_mask IS NULL)",
            name="ck_phone_events_mask_only_on_identity_match",
        ),
    )


class IdDocument(db.Model):
    """신분증 단계. 주민번호는 AES-256-GCM 암호문으로만 보관한다."""

    __tablename__ = "id_documents"

    verification_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("verifications.id", ondelete="CASCADE"), primary_key=True
    )
    name: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    rrn_enc: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    birth_date: Mapped[date] = mapped_column(sa.Date, nullable=False)
    issue_date: Mapped[date] = mapped_column(sa.Date, nullable=False)
    ci_matched: Mapped[bool | None] = mapped_column(sa.Boolean)
    # D4: W-09 증적·관리자 표시용
    mois_matched: Mapped[bool | None] = mapped_column(sa.Boolean)
    s3_key: Mapped[str | None] = mapped_column(sa.String(200))
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)

    verification: Mapped["Verification"] = relationship(back_populates="id_document")


class FaceCheck(db.Model):
    """얼굴 대조 시도 한 건. 시도마다 행을 남긴다."""

    __tablename__ = "face_checks"

    id: Mapped[int] = mapped_column(BIG_INT_PK, primary_key=True, autoincrement=True)
    verification_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("verifications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    s3_key: Mapped[str | None] = mapped_column(sa.String(200))
    face_count: Mapped[int | None] = mapped_column(sa.Integer)
    similarity: Mapped[Decimal | None] = mapped_column(sa.Numeric(5, 2))
    matched: Mapped[bool | None] = mapped_column(sa.Boolean)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)

    verification: Mapped["Verification"] = relationship(back_populates="face_checks")

    __table_args__ = (
        sa.CheckConstraint("face_count IS NULL OR face_count >= 0", name="ck_face_checks_count"),
        sa.CheckConstraint(
            "similarity IS NULL OR (similarity >= 0 AND similarity <= 100)",
            name="ck_face_checks_similarity",
        ),
    )


class MockMoisRegistry(db.Model):
    """모의 진위확인 대장. 주민번호는 HMAC 해시로만 보관한다(키 ekyc/mois-key)."""

    __tablename__ = "mock_mois_registry"

    id: Mapped[int] = mapped_column(BIG_INT_PK, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    rrn_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    issue_date: Mapped[date] = mapped_column(sa.Date, nullable=False)
    status: Mapped[str] = mapped_column(sa.String(10), nullable=False, default="정상")

    __table_args__ = (
        sa.CheckConstraint(_in_list("status", MOIS_STATUSES), name="ck_mock_mois_status"),
        sa.Index("ix_mock_mois_lookup", "name", "rrn_hash", "issue_date"),
    )
