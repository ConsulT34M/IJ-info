#!/usr/bin/env python3
"""인증 건 하나를 마스킹된 상태로 들여다본다(시연·점검용).

    .venv/bin/python tools/peek.py <verification_id>        # 전체 또는 앞부분만
    .venv/bin/python tools/peek.py --latest                 # 가장 최근 건

성명·휴대폰번호·주민번호는 마스킹해서 출력하고 CI는 보관 여부만 보여준다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402
from app.common import secrets as secret_store  # noqa: E402
from app.common.crypto import DecryptError, aad, decrypt_str  # noqa: E402
from app.common.log_mask import mask_name, mask_rrn  # noqa: E402
from app.common.timeutil import kst_display  # noqa: E402
from app.models import (  # noqa: E402
    AccessLog,
    Callback,
    FaceCheck,
    IdDocument,
    PhoneEvent,
    PhoneOtp,
    PhoneVerification,
    Verification,
    db,
)

LINE = "─" * 78


def find_verification(needle: str | None, latest: bool) -> Verification | None:
    if latest:
        return db.session.scalars(
            db.select(Verification).order_by(Verification.created_at.desc())
        ).first()
    rows = db.session.scalars(
        db.select(Verification)
        .where(db.cast(Verification.id, db.String).like(f"{needle}%"))
        .order_by(Verification.created_at.desc())
    ).all()
    if len(rows) > 1:
        print(f"앞부분이 겹치는 건이 {len(rows)}개다. 더 길게 넣는다.")
        for row in rows:
            print(f"  {row.id}  {kst_display(row.created_at)}  {row.status}")
        return None
    return rows[0] if rows else None


def masked_rrn(document: IdDocument | None) -> str:
    if document is None or document.rrn_enc is None:
        return "-"
    try:
        plain = decrypt_str(
            secret_store.get_key("ekyc/rrn-key"),
            document.rrn_enc,
            aad("id_documents", "rrn_enc", document.verification_id),
        )
    except DecryptError:
        return "(복호화 실패)"
    return mask_rrn(plain)


def ci_label(phone: PhoneVerification | None) -> str:
    if phone is None or not phone.ci:
        return "파기됨" if phone and phone.ci_purged_at else "없음"
    return f"보관 중({len(phone.ci)}자, 비표시)"


def show(verification: Verification) -> None:
    phone = verification.phone
    document = verification.id_document

    print(LINE)
    print(f"건 {verification.id}")
    print(LINE)
    print(f"  위탁사         : {verification.client.name} / {verification.client_user_ref}")
    print(f"  stage          : {verification.stage}")
    print(f"  status         : {verification.status}")
    print(f"  reason_code    : {verification.reason_code or '-'}")
    print(f"  last_error_code: {verification.last_error_code or '-'}")
    print(f"  얼굴 단계 시도  : {verification.face_attempts} / 3")
    print(f"  요청 / 만료     : {kst_display(verification.created_at)} / {kst_display(verification.expires_at)}")
    print(f"  종결           : {kst_display(verification.completed_at)}")
    print(f"  인증창 토큰     : {'사용됨' if verification.token_used_at else '미사용'}"
          f" (nonce {'있음' if verification.entry_nonce else '없음'})")

    print(f"\n[휴대폰]")
    if phone is None:
        print("  기록 없음")
    else:
        otp = db.session.get(PhoneOtp, verification.id)
        print(f"  상태           : {phone.status}")
        print(f"  명의 대조 시도  : {phone.match_attempts} / 3")
        print(f"  인증번호 시도   : {phone.otp_attempts} / 3")
        print(f"  인증번호 발송   : {otp.issue_no if otp else 0}회"
              f" (유효 {kst_display(otp.code_expires_at) if otp else '-'},"
              f" 검증값 {'보관' if otp and otp.code_mac else '폐기'})")
        print(f"  CI             : {ci_label(phone)}")
        print(f"  CI 첫 전달      : {kst_display(phone.ci_first_delivered_at)}")
        print(f"  CI 파기        : {kst_display(phone.ci_purged_at)}")
        print(f"  대조 토큰       : {'보관' if phone.match_token_enc else '폐기'}")

    print(f"\n[신분증]")
    if document is None:
        print("  기록 없음")
    else:
        print(f"  성명           : {mask_name(document.name)}")
        print(f"  주민번호        : {masked_rrn(document)}")
        print(f"  생년월일 / 발급  : {document.birth_date or '-'} / {document.issue_date or '-'}")
        print(f"  X-01 CI 대조    : {_flag(document.ci_matched)}")
        print(f"  진위확인        : {_flag(document.mois_matched)}")
        print(f"  이미지          : {'보관 중' if document.s3_key else '파기됨'}"
              f" ({kst_display(document.deleted_at)})")

    checks = db.session.scalars(
        db.select(FaceCheck).filter_by(verification_id=verification.id).order_by(FaceCheck.id)
    ).all()
    print(f"\n[얼굴] {len(checks)}회")
    for check in checks:
        print(f"  {kst_display(check.created_at)}  얼굴 {check.face_count}개"
              f"  유사도 {check.similarity if check.similarity is not None else '-'}"
              f"  {_flag(check.matched)}"
              f"  이미지 {'보관 중' if check.s3_key else '파기됨'}")

    events = db.session.scalars(
        db.select(PhoneEvent).filter_by(verification_id=verification.id).order_by(PhoneEvent.id)
    ).all()
    print(f"\n[phone_events] {len(events)}건")
    for event in events:
        print(f"  {kst_display(event.occurred_at)}  {event.event_kind:<15}"
              f" {event.result_code or '-':<5} {event.name_mask or '':<8} {event.phone_mask or ''}")

    logs = db.session.scalars(
        db.select(AccessLog)
        .where(db.or_(
            AccessLog.target_id == str(verification.id),
            AccessLog.target_id.like(f"{verification.id}%"),
        ))
        .order_by(AccessLog.id)
    ).all()
    print(f"\n[access_logs] {len(logs)}건")
    for log in logs:
        print(f"  {kst_display(log.created_at)}  {log.actor:<7} {log.action:<17}"
              f" {log.ip or '-':<15} {log.reason or ''}")

    callbacks = db.session.scalars(
        db.select(Callback).filter_by(verification_id=verification.id).order_by(Callback.id)
    ).all()
    print(f"\n[callbacks] {len(callbacks)}건")
    for row in callbacks:
        print(f"  {kst_display(row.sent_at)}  HTTP {row.http_status or '전송 실패'}"
              f"  재시도 {row.retry_count}  {row.url}")
    print(LINE)


def _flag(value: bool | None) -> str:
    if value is None:
        return "-"
    return "통과" if value else "불일치"


def main() -> int:
    parser = argparse.ArgumentParser(description="인증 건 들여다보기(마스킹)")
    parser.add_argument("verification_id", nargs="?", help="전체 또는 앞부분")
    parser.add_argument("--latest", action="store_true", help="가장 최근 건")
    args = parser.parse_args()

    if not args.verification_id and not args.latest:
        parser.error("verification_id 또는 --latest 가 필요하다")

    app = create_app()
    with app.app_context():
        verification = find_verification(args.verification_id, args.latest)
        if verification is None:
            print("해당 건을 찾을 수 없다.")
            return 1
        show(verification)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
