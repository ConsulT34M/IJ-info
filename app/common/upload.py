"""업로드 이미지 검사: 확장자 + 매직바이트 + 용량 (W-04).

모든 실패는 호출부에서 E01로 묶는다. 내부 error 값은 로그·증적용이다.
"""

from __future__ import annotations

from dataclasses import dataclass

# 확장자 → 허용 매직바이트
MAGIC_BYTES = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
}


@dataclass(frozen=True)
class UploadCheck:
    """업로드 검사 결과."""

    ok: bool
    data: bytes | None = None
    extension: str | None = None
    hint: str = ""
    error: str | None = None  # EMPTY / EXTENSION / SIZE / MAGIC


def _extension_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def validate_image_upload(
    file_storage,
    *,
    max_bytes: int,
    allowed_extensions: tuple[str, ...],
) -> UploadCheck:
    """업로드 파일을 검사해 바이트를 돌려준다. 파일명은 저장하지 않고 힌트로만 쓴다."""
    if file_storage is None or not getattr(file_storage, "filename", ""):
        return UploadCheck(ok=False, error="EMPTY")

    filename = file_storage.filename
    extension = _extension_of(filename)
    if extension not in {ext.lower() for ext in allowed_extensions}:
        return UploadCheck(ok=False, hint=filename, error="EXTENSION")

    # 용량 초과를 알아내기 위해 한 바이트 더 읽는다
    data = file_storage.read(max_bytes + 1)
    if not data:
        return UploadCheck(ok=False, hint=filename, error="EMPTY")
    if len(data) > max_bytes:
        return UploadCheck(ok=False, hint=filename, error="SIZE")

    if not any(data.startswith(magic) for magic in MAGIC_BYTES.get(extension, ())):
        return UploadCheck(ok=False, hint=filename, error="MAGIC")

    return UploadCheck(ok=True, data=data, extension=extension, hint=filename)
