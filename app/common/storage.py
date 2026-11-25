"""이미지 저장소. 로컬 구현과 S3 구현을 바꿔 끼울 수 있게 인터페이스로 둔다.

- 업로드 파일은 웹 루트 밖(instance/uploads)에 UUID 파일명으로 저장한다(W-04).
- 키에는 경로 구분자를 넣지 않고, 형식을 검사해 경로 조작을 막는다.
"""

from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

from flask import current_app

KEY_PATTERN = re.compile(r"^[0-9a-f]{32}\.(jpg|jpeg|png)$")


class StorageError(RuntimeError):
    """저장소 오류."""


class Storage(ABC):
    """이미지 저장소 인터페이스."""

    @abstractmethod
    def save(self, data: bytes, extension: str) -> str:
        """저장하고 키를 돌려준다."""

    @abstractmethod
    def load(self, key: str) -> bytes:
        """키로 읽는다. 없으면 StorageError."""

    @abstractmethod
    def delete(self, key: str) -> bool:
        """지운다. 이미 없으면 False."""

    @abstractmethod
    def exists(self, key: str) -> bool:
        """있는지 본다."""

    @staticmethod
    def new_key(extension: str) -> str:
        """UUID 파일명. 원본 파일명은 쓰지 않는다."""
        ext = extension.lower().lstrip(".")
        key = f"{uuid.uuid4().hex}.{ext}"
        if not KEY_PATTERN.match(key):
            raise StorageError(f"허용되지 않은 확장자다: {extension}")
        return key

    @staticmethod
    def check_key(key: str) -> str:
        """경로 조작을 막기 위해 키 형식을 검사한다."""
        if not isinstance(key, str) or not KEY_PATTERN.match(key):
            raise StorageError("저장소 키 형식이 올바르지 않다")
        return key


class LocalStorage(Storage):
    """로컬 파일 저장소(개발·실습용)."""

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)

    def _path(self, key: str) -> Path:
        return self.base_dir / self.check_key(key)

    def save(self, data: bytes, extension: str) -> str:
        key = self.new_key(extension)
        self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.base_dir / key
        path.write_bytes(data)
        path.chmod(0o600)
        return key

    def load(self, key: str) -> bytes:
        path = self._path(key)
        if not path.exists():
            raise StorageError("저장소에 파일이 없다")
        return path.read_bytes()

    def delete(self, key: str) -> bool:
        path = self._path(key)
        if not path.exists():
            return False
        path.unlink()
        return True

    def exists(self, key: str) -> bool:
        return self._path(key).exists()


class S3Storage(Storage):
    """AWS 배포용 자리(이번 범위에서는 호출하지 않는다)."""

    def __init__(self, bucket: str, prefix: str = ""):
        self.bucket = bucket
        self.prefix = prefix

    def _not_yet(self):
        raise NotImplementedError("S3Storage는 AWS 배포 단계에서 구현한다")

    def save(self, data: bytes, extension: str) -> str:
        self._not_yet()

    def load(self, key: str) -> bytes:
        self._not_yet()

    def delete(self, key: str) -> bool:
        self._not_yet()

    def exists(self, key: str) -> bool:
        self._not_yet()


def build_storage(config) -> Storage:
    """설정에 맞는 저장소를 만든다."""
    backend = str(config.get("STORAGE_BACKEND", "local")).lower()
    if backend == "s3":
        return S3Storage(config["S3_BUCKET"], config.get("S3_PREFIX", ""))
    return LocalStorage(config["UPLOAD_DIR"])


def get_storage() -> Storage:
    """현재 앱에 붙은 저장소."""
    return current_app.extensions["storage"]
