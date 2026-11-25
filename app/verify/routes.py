"""IA-02 인증창 진입, IA-03 동의, IA-10 취소. 휴대폰 입력 화면(4단계 POST 전)까지."""

from __future__ import annotations

import time

from flask import Blueprint, abort, current_app, g, redirect, render_template, request

from app.common.client_ip import client_ip
from app.common.crypto import sha256_hex
from app.common.stage import (
    advance_stage,
    end_session,
    require_stage,
    stage_redirect,
    start_session,
)
from app.common.timeutil import is_expired, now_utc, seconds_left
from app.models import CONSENT_TYPES, Consent, Verification, db
from app.verify.termination import terminate

bp = Blueprint("verify", __name__, url_prefix="/verify")

# 취소는 종결 전 모든 단계에서 받는다(5장)
CANCELLABLE_STAGES = ("CONSENT", "PHONE", "ID_CARD", "ID_CONFIRM", "FACE")


@bp.get("/start/<token>")
def start(token: str):
    """IA-02. 토큰을 1회만 쓰고 서버 세션으로 바꾼 뒤 토큰 없는 주소로 보낸다."""
    expires_at, _, random_part = token.partition(".")
    if not expires_at.isdigit() or not random_part:
        abort(410, description="인증창 주소가 올바르지 않다.")
    if int(time.time()) > int(expires_at):
        abort(410, description="인증창 주소가 만료됐다. 거래소에서 다시 시작한다.")

    # 1회 사용 처리를 원자적 UPDATE로 한다(동시 진입 시 한 번만 성공)
    used = db.session.execute(
        db.update(Verification)
        .where(
            Verification.token_hash == sha256_hex(token),
            Verification.token_used_at.is_(None),
            Verification.status == "PENDING",
        )
        .values(token_used_at=now_utc())
    )
    if used.rowcount != 1:
        db.session.rollback()
        abort(410, description="이미 사용했거나 만료된 인증창 주소다.")
    db.session.commit()

    verification = db.session.scalars(
        db.select(Verification).filter_by(token_hash=sha256_hex(token))
    ).one()

    if is_expired(verification.expires_at):
        terminate(verification, "P03")
        abort(410, description="인증 제한 시간이 지났다. 거래소에서 다시 시작한다.")

    start_session(verification)
    current_app.logger.info("인증창 진입: verification_id=%s", verification.id)
    return stage_redirect(verification)


@bp.get("/consent")
@require_stage("CONSENT")
def consent_page():
    """동의 화면."""
    return render_template(
        "verify/consent.html",
        consent_types=CONSENT_TYPES,
        versions=current_app.config["CONSENT_VERSIONS"],
        seconds_left=int(seconds_left(g.verification.expires_at)),
    )


@bp.post("/consent")
@require_stage("CONSENT")
def consent_submit():
    """IA-03. 동의 4종을 모두 받아야 다음 단계로 간다."""
    verification = g.verification
    versions = current_app.config["CONSENT_VERSIONS"]

    missing = [name for name in CONSENT_TYPES if request.form.get(name) != "on"]
    if missing:
        return (
            render_template(
                "verify/consent.html",
                consent_types=CONSENT_TYPES,
                versions=versions,
                error="필수 동의 4종에 모두 동의해야 진행할 수 있다.",
                seconds_left=int(seconds_left(verification.expires_at)),
            ),
            400,
        )

    # 화면에 표시한 약관 버전과 서버 버전이 다르면 다시 받는다
    for name in CONSENT_TYPES:
        if request.form.get(f"{name}_version") != versions[name]:
            abort(400, description="약관 버전이 바뀌었다. 처음부터 다시 진행한다.")

    agreed_at = now_utc()
    ip = client_ip()
    for name in CONSENT_TYPES:
        db.session.add(
            Consent(
                verification_id=verification.id,
                type=name,
                version=versions[name],
                agreed_at=agreed_at,
                ip=ip,
            )
        )
    advance_stage(verification, "PHONE")
    db.session.commit()
    current_app.logger.info("동의 완료: verification_id=%s", verification.id)
    return stage_redirect(verification)


@bp.get("/phone")
@require_stage("PHONE")
def phone_page():
    """휴대폰 정보 입력 화면. 전송 처리(IA-04)는 4단계에서 붙인다."""
    return render_template(
        "verify/phone.html",
        seconds_left=int(seconds_left(g.verification.expires_at)),
    )


@bp.post("/cancel")
@require_stage(*CANCELLABLE_STAGES)
def cancel():
    """IA-10. 이용자 취소 → P04 종결 후 return_url로 보낸다."""
    verification = g.verification
    return_url = verification.return_url
    terminate(verification, "P04")  # FAILED 이력·웹훅은 terminate가 남긴다
    end_session()
    return redirect(return_url)
