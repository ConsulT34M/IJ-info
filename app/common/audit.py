"""access_logs·phone_events 기록 헬퍼. INSERT만 한다(UPDATE/DELETE 없음).

commit은 호출부에서 한다. 같은 트랜잭션에 묶여야 기록이 빠지지 않는다.
"""

from __future__ import annotations

from app.models import AccessLog, PhoneEvent, db


def log_access(
    actor: str,
    action: str,
    *,
    actor_id: str | None = None,
    target_id: str | None = None,
    reason: str | None = None,
    ip: str | None = None,
) -> AccessLog:
    """접속·열람 기록 한 줄."""
    row = AccessLog(
        actor=actor,
        actor_id=str(actor_id) if actor_id is not None else None,
        action=action,
        target_id=str(target_id) if target_id is not None else None,
        reason=reason,
        ip=ip,
    )
    db.session.add(row)
    return row


def log_phone_event(
    verification_id,
    event_kind: str,
    *,
    result_code: str | None = None,
    name_mask: str | None = None,
    phone_mask: str | None = None,
) -> PhoneEvent:
    """휴대폰 단계 이력 한 줄. 마스킹값은 IDENTITY_MATCH에서만 넣을 수 있다."""
    row = PhoneEvent(
        verification_id=verification_id,
        event_kind=event_kind,
        result_code=result_code,
        name_mask=name_mask,
        phone_mask=phone_mask,
    )
    db.session.add(row)
    return row
