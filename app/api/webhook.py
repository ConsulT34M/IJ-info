"""결과 웹훅(IA-11) 전송과 결과 조회(IA-12)에 쓰는 공통 payload.

- 판정 시 1회만 보낸다(타임아웃 3초). 유실은 IA-12로 보완한다.
- 실패·취소·만료 웹훅에는 name·birth_date·ci_mock을 넣지 않는다.
- 서명은 위탁사별 HMAC Secret으로 A사가 만든다(X-Timestamp, X-Signature).
"""

from __future__ import annotations

import json
import time

import requests
from flask import current_app

from app.common import secrets as secret_store
from app.common.audit import log_access, log_phone_event
from app.common.crypto import sha256_hex
from app.common.hmac_auth import build_signature
from app.common.timeutil import kst_isoformat, now_utc
from app.models import Callback, Verification, db

PRODUCT = "ONBOARDING"
STAGE_PASSED = "PASSED"
STAGE_FAILED = "FAILED"
STAGE_NOT_STARTED = "NOT_STARTED"


def stage_states(verification: Verification) -> dict[str, str]:
    """단계별 상태. PASSED / FAILED / NOT_STARTED."""
    phone = verification.phone
    if phone is None:
        phone_state = STAGE_NOT_STARTED
    elif phone.status == "PASSED":
        phone_state = STAGE_PASSED
    elif phone.status == "FAILED":
        phone_state = STAGE_FAILED
    else:
        phone_state = STAGE_NOT_STARTED

    document = verification.id_document
    if document is None:
        id_card_state = STAGE_NOT_STARTED
    elif document.ci_matched and document.mois_matched:
        id_card_state = STAGE_PASSED
    else:
        id_card_state = STAGE_FAILED

    checks = verification.face_checks
    if not checks:
        face_state = STAGE_NOT_STARTED
    elif any(check.matched for check in checks):
        face_state = STAGE_PASSED
    else:
        face_state = STAGE_FAILED

    return {"phone": phone_state, "id_card": id_card_state, "face": face_state}


def build_result_payload(verification: Verification) -> dict:
    """웹훅·IA-12가 함께 쓰는 결과 본문(7장)."""
    succeeded = verification.status == "SUCCEEDED"
    payload = {
        "product": PRODUCT,
        "verification_id": str(verification.id),
        "status": verification.status,
        "reason_code": verification.reason_code,
        "stages": stage_states(verification),
    }

    if succeeded:
        document = verification.id_document
        phone = verification.phone
        if document is not None:
            payload["name"] = document.name
            payload["birth_date"] = document.birth_date.isoformat()
        if phone is not None and phone.ci:
            payload["ci_mock"] = phone.ci

    payload["verified_at"] = kst_isoformat(verification.completed_at) if succeeded else None
    return payload


def encode_payload(payload: dict) -> bytes:
    """서명 대상이 되는 원본 바이트. 거래소도 같은 바이트에 서명을 검증한다."""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def post_json(url: str, body: bytes, headers: dict, timeout: float):
    """웹훅 HTTP 전송. 테스트는 이 함수만 바꿔 끼운다(통신사 호출과 분리)."""
    return requests.post(url, data=body, headers=headers, timeout=timeout)


def was_sent(verification: Verification) -> bool:
    """이미 보낸 건인지 본다(1회 전송)."""
    return bool(
        db.session.scalar(
            db.select(db.func.count())
            .select_from(Callback)
            .filter_by(verification_id=verification.id)
        )
    )


def mark_ci_delivered(verification: Verification) -> None:
    """CI 첫 전달 시각을 기록한다(보관기한 7일의 기준)."""
    phone = verification.phone
    if phone is None or not phone.ci or phone.ci_first_delivered_at is not None:
        return
    phone.ci_first_delivered_at = now_utc()
    log_phone_event(verification.id, "CI_DELIVERED")


def send_result_webhook(verification: Verification) -> Callback | None:
    """판정 결과를 거래소로 1회 보낸다. 실패해도 예외를 올리지 않는다."""
    if was_sent(verification):
        return None

    client = verification.client
    payload = build_result_payload(verification)
    body = encode_payload(payload)
    timestamp = str(int(time.time()))
    secret = secret_store.get_secret(client.hmac_secret_ref)

    http_status = None
    try:
        response = post_json(
            client.callback_url,
            body,
            {
                "Content-Type": "application/json",
                "X-Timestamp": timestamp,
                "X-Signature": build_signature(secret, timestamp, body),
            },
            current_app.config["WEBHOOK_TIMEOUT"],
        )
        http_status = response.status_code
    except requests.RequestException as exc:
        current_app.logger.warning(
            "웹훅 전송 실패: verification_id=%s 사유=%s", verification.id, exc.__class__.__name__
        )

    record = Callback(
        verification_id=verification.id,
        url=client.callback_url,
        payload_hash=sha256_hex(body),
        http_status=http_status,
        retry_count=0,
    )
    db.session.add(record)
    log_access(
        "system",
        "CALLBACK_SENT",
        actor_id=str(client.id),
        target_id=str(verification.id),
    )

    if http_status == 200 and "ci_mock" in payload:
        mark_ci_delivered(verification)

    db.session.commit()
    current_app.logger.info(
        "웹훅 전송: verification_id=%s status=%s http=%s",
        verification.id,
        verification.status,
        http_status,
    )
    return record
