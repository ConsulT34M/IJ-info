"""얼굴 단계 진입 요건과 시도 횟수. 인증창(IA-09)과 서버 간 API(IA-22)가 함께 쓴다.

두 경로가 같은 함수를 쓰게 둬야 한쪽만 느슨해지는 일이 없다(D87).

- D2: 최종 판정은 플래그와 무관하게 항상 `id_documents.ci_matched IS TRUE`를 요구한다.
  `VULN_W09`는 진위확인(`mois_matched`) 확인만 뺀다.
- D8/D10: 얼굴 단계 실패(E01~E05)는 한 카운터에 합산하고 중간 코드는 last_error_code에 남긴다.
"""

from __future__ import annotations

from flask import abort, current_app

from app.models import IdDocument, Verification, db


def require_id_document(verification: Verification) -> IdDocument:
    """얼굴 단계 요구사항. 통과하지 못하면 403으로 끊는다."""
    document = db.session.get(IdDocument, verification.id)
    if document is None or not document.s3_key:
        abort(403, description="신분증 사진을 먼저 등록해 주세요.")
    if not document.ci_matched:
        current_app.logger.warning(
            "CI 대조 없이 얼굴 단계 요청: verification_id=%s", verification.id
        )
        abort(403, description="신분증 확인을 먼저 완료해 주세요.")
    # 양호 기본값: 진위확인 통과도 확인한다. VULN_W09를 켜면 이 확인만 빠진다.
    if not current_app.config.get("VULN_W09") and not document.mois_matched:
        current_app.logger.warning(
            "진위확인 없이 얼굴 단계 요청: verification_id=%s", verification.id
        )
        abort(403, description="신분증 확인을 먼저 완료해 주세요.")
    return document


def bump_face_attempts(verification: Verification, code: str) -> int:
    """얼굴 단계 시도(E01~E05 합산)를 올리고 중간 실패 코드를 남긴다(D8, D10)."""
    verification.face_attempts += 1
    verification.last_error_code = code
    db.session.commit()
    return verification.face_attempts


def attempts_exhausted(attempts: int) -> bool:
    """합산 시도가 상한에 닿았는지. 닿으면 호출부가 E06으로 종결한다."""
    return attempts >= current_app.config["FACE_MAX_ATTEMPTS"]


def attempts_left(attempts: int) -> int:
    return max(0, current_app.config["FACE_MAX_ATTEMPTS"] - attempts)
