"""MC-01 명의 대조, MC-02 CI 발급, MC-03 본인확인 앱 기기 등록용 명의 확인."""

from __future__ import annotations

import functools
from secrets import token_urlsafe

from flask import Blueprint, abort, current_app, g, jsonify, request

from app.common import secrets as secret_store
from app.common.ci import ci_mock
from app.common.crypto import decrypt_str, hmac_sha256_hex, sha256_hex
from app.common.log_mask import mask_name, mask_phone
from app.common.rrn import birth_date_from_rrn
from app.common.timeutil import is_expired, kst_isoformat, now_utc
from carrier.models import CarrierClient, MatchSession, Subscriber, db

bp = Blueprint("carrier", __name__, url_prefix="/carrier/v1")

# MC-01이 돌려주는 내부용 사유 (D1). A사는 기본(양호)에서 둘을 P01 하나로 합친다.
REASON_NAME_MISMATCH = "NAME_MISMATCH"
REASON_NOT_SUBSCRIBER = "NOT_SUBSCRIBER"
# MC-03에서만 쓰는 사유. 기기 등록은 생년월일까지 본다.
REASON_BIRTH_MISMATCH = "BIRTH_MISMATCH"


def normalize_phone(value: object) -> str | None:
    """하이픈·공백을 떼고 010으로 시작하는 11자리만 받는다."""
    if not isinstance(value, str):
        return None
    digits = "".join(ch for ch in value if ch.isdigit())
    return digits if len(digits) == 11 and digits.startswith("010") else None


def require_carrier_client(view):
    """X-Carrier-Client-Key 헤더를 키 해시와 대조한다."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        presented = request.headers.get("X-Carrier-Client-Key", "")
        if not presented:
            abort(401, description="클라이언트 키가 없다.")
        row = db.session.scalars(
            db.select(CarrierClient).filter_by(key_digest=sha256_hex(presented))
        ).one_or_none()
        if row is None or row.status != "ACTIVE":
            current_app.logger.warning("통신사 API 키 거부: ip=%s", request.remote_addr)
            abort(401, description="클라이언트 키가 올바르지 않다.")
        g.carrier_client = row
        return view(*args, **kwargs)

    return wrapper


def _json_body() -> dict:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON 본문이 필요하다.")
    return payload


@bp.post("/identity-matches")
@require_carrier_client
def identity_matches():
    """MC-01. 성명·휴대폰번호를 명부와 대조한다. 일치하면 5분짜리 대조 토큰을 준다."""
    payload = _json_body()
    verification_id = payload.get("verification_id")
    name = payload.get("name")
    phone = normalize_phone(payload.get("phone_number"))

    if not isinstance(verification_id, str) or not verification_id.strip():
        abort(400, description="verification_id가 필요하다.")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 50:
        abort(400, description="name이 필요하다.")
    if phone is None:
        abort(400, description="phone_number 형식이 올바르지 않다.")

    subscriber_key = secret_store.get_key("carrier/subscriber-key")
    subscriber = db.session.scalars(
        db.select(Subscriber).filter_by(phone_key=hmac_sha256_hex(subscriber_key, phone))
    ).one_or_none()

    if subscriber is None:
        current_app.logger.info(
            "MC-01 미등록 번호: verification_id=%s phone=%s", verification_id, mask_phone(phone)
        )
        return jsonify(matched=False, reason=REASON_NOT_SUBSCRIBER), 200

    if subscriber.name_mac != hmac_sha256_hex(subscriber_key, name.strip()):
        current_app.logger.info(
            "MC-01 명의 불일치: verification_id=%s name=%s", verification_id, mask_name(name)
        )
        return jsonify(matched=False, reason=REASON_NAME_MISMATCH), 200

    token = token_urlsafe(32)
    expires_at = now_utc() + current_app.config["MATCH_TOKEN_TTL"]
    db.session.add(
        MatchSession(
            token_digest=sha256_hex(token),
            subscriber_ref=subscriber.subscriber_ref,
            verification_id=verification_id.strip(),
            expires_at=expires_at,
        )
    )
    db.session.commit()
    current_app.logger.info("MC-01 일치: verification_id=%s", verification_id)

    return (
        jsonify(
            matched=True,
            reason=None,
            match_token=token,
            expires_at=kst_isoformat(expires_at),
        ),
        200,
    )


@bp.post("/ci-issuances")
@require_carrier_client
def ci_issuances():
    """MC-02. 대조 토큰 1회용으로 CI(88자)를 발급한다."""
    payload = _json_body()
    verification_id = payload.get("verification_id")
    match_token = payload.get("match_token")

    if not isinstance(verification_id, str) or not isinstance(match_token, str) or not match_token:
        abort(400, description="verification_id와 match_token이 필요하다.")

    digest = sha256_hex(match_token)
    session_row = db.session.get(MatchSession, digest)
    if (
        session_row is None
        or session_row.used_at is not None
        or session_row.verification_id != verification_id.strip()
        or is_expired(session_row.expires_at)
    ):
        current_app.logger.warning("MC-02 토큰 거부: verification_id=%s", verification_id)
        abort(409, description="대조 토큰을 쓸 수 없다.")

    # 1회용 보장: 조건부 원자적 UPDATE가 1행을 바꿔야 통과
    used = db.session.execute(
        db.update(MatchSession)
        .where(MatchSession.token_digest == digest, MatchSession.used_at.is_(None))
        .values(used_at=now_utc())
    )
    if used.rowcount != 1:
        db.session.rollback()
        abort(409, description="대조 토큰을 쓸 수 없다.")
    db.session.commit()

    subscriber = db.session.get(Subscriber, session_row.subscriber_ref)
    rrn = decrypt_str(
        secret_store.get_key("carrier/rrn-key"),
        subscriber.rrn_ciphertext,
        _subscriber_aad(subscriber.subscriber_ref),
    )
    current_app.logger.info("MC-02 CI 발급: verification_id=%s", verification_id)
    return jsonify(ci=ci_mock(rrn, secret_store.get_key("carrier/ci-key"))), 200


@bp.post("/device-registrations")
@require_carrier_client
def device_registrations():
    """MC-03. 본인확인 앱(PASS) 기기 등록 전 명의 확인.

    실제 PASS 앱을 깔 때 하는 "통신사 명의 인증"에 해당한다. MC-01과 달리
    생년월일까지 보고, 대조 토큰은 주지 않는다. CI 발급으로 이어지지 않는다(D85).
    """
    payload = _json_body()
    name = payload.get("name")
    phone = normalize_phone(payload.get("phone_number"))
    birth_date = payload.get("birth_date")

    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 50:
        abort(400, description="name이 필요하다.")
    if phone is None:
        abort(400, description="phone_number 형식이 올바르지 않다.")
    if not isinstance(birth_date, str) or len(birth_date.strip()) != 10:
        abort(400, description="birth_date는 YYYY-MM-DD 형식이다.")

    subscriber_key = secret_store.get_key("carrier/subscriber-key")
    subscriber = db.session.scalars(
        db.select(Subscriber).filter_by(phone_key=hmac_sha256_hex(subscriber_key, phone))
    ).one_or_none()

    if subscriber is None:
        current_app.logger.info("MC-03 미등록 번호: phone=%s", mask_phone(phone))
        return jsonify(matched=False, reason=REASON_NOT_SUBSCRIBER), 200

    if subscriber.name_mac != hmac_sha256_hex(subscriber_key, name.strip()):
        current_app.logger.info("MC-03 명의 불일치: name=%s", mask_name(name))
        return jsonify(matched=False, reason=REASON_NAME_MISMATCH), 200

    rrn = decrypt_str(
        secret_store.get_key("carrier/rrn-key"),
        subscriber.rrn_ciphertext,
        _subscriber_aad(subscriber.subscriber_ref),
    )
    registered_birth = birth_date_from_rrn(rrn)
    if registered_birth is None or registered_birth.isoformat() != birth_date.strip():
        current_app.logger.info("MC-03 생년월일 불일치: phone=%s", mask_phone(phone))
        return jsonify(matched=False, reason=REASON_BIRTH_MISMATCH), 200

    current_app.logger.info("MC-03 기기 등록 명의 확인: phone=%s", mask_phone(phone))
    return jsonify(matched=True, reason=None, phone_mask=mask_phone(phone)), 200


def _subscriber_aad(subscriber_ref: str) -> bytes:
    """D17: 암호문을 가입자 행에 묶는다."""
    from app.common.crypto import aad

    return aad("subscriber", "rrn_ciphertext", subscriber_ref)
