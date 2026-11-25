"""업로드 이미지 파기.

최종 판정·종결 시 Storage에서 객체를 지우고 DB 참조를 비운다(s3_key NULL + deleted_at).
`delete_objects=False`는 "DB 참조만 지우고 객체는 남기는" 상태를 만든다 — 파기 배치의
VULN_C10 실습(9단계)에서만 쓴다.
"""

from __future__ import annotations

from flask import current_app

from app.common.storage import StorageError, get_storage
from app.common.timeutil import now_utc


def delete_verification_images(verification, *, delete_objects: bool = True) -> int:
    """건에 남아 있는 이미지를 파기한다. 지운 참조 수를 돌려준다(commit은 호출부에서)."""
    storage = get_storage()
    purged = 0
    now = now_utc()

    targets = []
    document = verification.id_document
    if document is not None and document.s3_key:
        targets.append(document)
    targets.extend(check for check in verification.face_checks if check.s3_key)

    for row in targets:
        key = row.s3_key
        if delete_objects:
            try:
                storage.delete(key)
            except StorageError:
                current_app.logger.warning(
                    "이미지 파기 실패(키 오류): verification_id=%s", verification.id
                )
        row.s3_key = None
        row.deleted_at = now
        purged += 1

    if purged:
        current_app.logger.info(
            "이미지 파기: verification_id=%s 건수=%s 객체삭제=%s",
            verification.id,
            purged,
            delete_objects,
        )
    return purged
