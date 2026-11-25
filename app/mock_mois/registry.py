"""모의 진위확인 대장 조회."""

from __future__ import annotations

from datetime import date

from app.common import secrets as secret_store
from app.common.crypto import hmac_sha256_hex
from app.common.rrn import normalize_rrn
from app.models import MockMoisRegistry, db

STATUS_NORMAL = "정상"


def rrn_hash(rrn: str) -> str:
    """대장 조회용 해시."""
    digits = normalize_rrn(rrn)
    if digits is None:
        raise ValueError("주민번호 13자리가 필요하다")
    return hmac_sha256_hex(secret_store.get_key("ekyc/mois-key"), digits)


def verify(name: str, rrn: str, issue_date: date) -> bool:
    """성명 + 주민번호 + 발급일자가 대장과 모두 맞고 상태가 정상이면 True.

    불일치·미등록·분실은 모두 False다(이용자에게는 E03 한 가지로 보여준다).
    """
    if not name or not isinstance(issue_date, date):
        return False
    try:
        digest = rrn_hash(rrn)
    except ValueError:
        return False

    row = db.session.scalars(
        db.select(MockMoisRegistry).filter_by(rrn_hash=digest)
    ).one_or_none()
    if row is None:
        return False
    return row.name == name.strip() and row.issue_date == issue_date and row.status == STATUS_NORMAL
