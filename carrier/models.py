"""모의 통신사 SQLite 모델 (3개 테이블).

A사와 별도 앱·별도 DB·별도 키를 쓴다. 가입자 번호와 성명은 원문으로 두지 않는다.
"""

from __future__ import annotations

from datetime import datetime

import sqlalchemy as sa
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.common.timeutil import now_utc


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)

CLIENT_STATUSES = ("ACTIVE", "SUSPENDED")


class Subscriber(db.Model):
    """가입자 명부. 번호·성명은 통신사 자체 키로 HMAC하고, 주민번호는 암호문으로 둔다."""

    __tablename__ = "subscriber"

    subscriber_ref: Mapped[str] = mapped_column(sa.String(20), primary_key=True)
    phone_key: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    name_mac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    name_mask: Mapped[str] = mapped_column(sa.String(20), nullable=False)
    rrn_ciphertext: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    registered_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)


class MatchSession(db.Model):
    """명의 대조 성공 1건. 토큰은 해시로만 보관하고 verification_id에 묶인다."""

    __tablename__ = "match_session"

    token_digest: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    subscriber_ref: Mapped[str] = mapped_column(
        sa.ForeignKey("subscriber.subscriber_ref", ondelete="CASCADE"), nullable=False
    )
    verification_id: Mapped[str] = mapped_column(sa.String(36), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(sa.DateTime)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime, nullable=False, default=now_utc)


class CarrierClient(db.Model):
    """통신사 API를 쓸 수 있는 사업자(A사). 키는 해시로만 보관한다."""

    __tablename__ = "carrier_client"

    client_id: Mapped[str] = mapped_column(sa.String(50), primary_key=True)
    key_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(10), nullable=False, default="ACTIVE")

    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'SUSPENDED')", name="ck_carrier_client_status"
        ),
    )
