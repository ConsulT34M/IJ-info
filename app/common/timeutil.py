"""시각 처리. DB에는 naive UTC로 저장하고, 화면·웹훅은 KST로 바꿔 보여준다(D23).

PostgreSQL과 SQLite(테스트)에서 같은 값이 나오게 하려고 tz 없는 UTC를 쓴다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))


def now_utc() -> datetime:
    """현재 시각(naive UTC). DB 저장·비교에 쓴다."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_kst(value: datetime | None) -> datetime | None:
    """naive UTC를 KST(+09:00) aware 값으로 바꾼다."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(KST)


def kst_isoformat(value: datetime | None) -> str | None:
    """웹훅·API 응답용 '2026-11-26T14:03:21+09:00' 문자열."""
    kst = to_kst(value)
    return kst.replace(microsecond=0).isoformat() if kst else None


def seconds_left(deadline: datetime | None, now: datetime | None = None) -> float:
    """남은 초. 이미 지났으면 0."""
    if deadline is None:
        return 0.0
    return max(0.0, (deadline - (now or now_utc())).total_seconds())


def is_expired(deadline: datetime | None, now: datetime | None = None) -> bool:
    """만료 여부. deadline이 없으면 만료로 본다."""
    if deadline is None:
        return True
    return (now or now_utc()) >= deadline
