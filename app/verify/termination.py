"""인증 건 종결. 종결된 건은 다시 열지 않는다(거래소가 새 IA-01로 처음부터).

판정·실패·취소·만료가 모두 여기를 지난다. 웹훅은 여기서 1회 보낸다.
"""

from __future__ import annotations

from flask import current_app

from app.api.webhook import send_result_webhook
from app.common.audit import log_phone_event
from app.common.images import delete_verification_images
from app.common.timeutil import now_utc
from app.models import Verification, db

# 사유 코드 → 종결 상태
STATUS_BY_REASON = {
    "OK": "SUCCEEDED",
    "P03": "EXPIRED",
    "P04": "CANCELLED",
}


def status_for(reason_code: str) -> str:
    """사유 코드에 맞는 status. 나머지는 모두 FAILED."""
    return STATUS_BY_REASON.get(reason_code, "FAILED")


def terminate(verification: Verification, reason_code: str, *, notify: bool = True) -> None:
    """건을 종결하고 결과 웹훅을 보낸다. 이미 종결된 건은 그대로 둔다.

    동시에 두 요청이 종결을 시도해도(예: 취소 버튼 두 번) **조건부 UPDATE로 선점**해서
    종결과 웹훅이 한 번만 일어나게 한다.
    """
    if verification.is_finished:
        return

    status = status_for(reason_code)
    claimed = db.session.execute(
        db.update(Verification)
        .where(Verification.id == verification.id, Verification.status == "PENDING")
        .values(
            status=status,
            reason_code=reason_code,
            stage="DONE",
            completed_at=now_utc(),
            # 인증창 토큰은 더 쓸 수 없게 한다
            entry_nonce=None,
        )
    )
    if claimed.rowcount != 1:
        db.session.rollback()
        current_app.logger.info(
            "이미 종결된 건이라 그대로 둔다: verification_id=%s", verification.id
        )
        return
    db.session.refresh(verification)

    phone = verification.phone
    if phone is not None:
        phone.match_token_enc = None  # 종결 시 대조 토큰 폐기
        if phone.status == "PENDING":
            phone.status = "FAILED"
        if phone.completed_at is None:
            phone.completed_at = verification.completed_at

    if status != "SUCCEEDED":
        log_phone_event(verification.id, "FAILED", result_code=reason_code)

    # 판정 즉시 이미지를 파기한다(성공·실패 모두)
    delete_verification_images(verification)

    db.session.commit()
    current_app.logger.info(
        "건 종결: verification_id=%s status=%s reason=%s",
        verification.id,
        status,
        reason_code,
    )

    if notify:
        send_result_webhook(verification)
