"""얼굴 검출·대조. 로컬은 FakeFaceMatcher, 나중에 Rekognition으로 바꿔 끼운다.

FakeFaceMatcher 규칙(2장): 기본 얼굴 1개·유사도 95.
파일명에 `noface` → 얼굴 0개, `twofaces` → 2개, `mismatch` → 유사도 40.
원본 파일명은 저장하지 않고 판정에만 쓴다(힌트).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from flask import current_app

DEFAULT_SIMILARITY = 95.0
MISMATCH_SIMILARITY = 40.0


@dataclass(frozen=True)
class FaceComparison:
    """얼굴 대조 결과. face_checks에 그대로 들어간다."""

    face_count: int
    similarity: float | None
    matched: bool


class FaceMatcher(ABC):
    """얼굴 검출·대조 인터페이스."""

    @abstractmethod
    def detect_face_count(self, image: bytes, *, hint: str = "") -> int:
        """이미지에서 검출된 얼굴 수."""

    @abstractmethod
    def compare_faces(
        self, source: bytes, target: bytes, *, hint: str = "", threshold: float = 90.0
    ) -> FaceComparison:
        """신분증 사진(source)과 셀카(target)를 대조한다."""


class FakeFaceMatcher(FaceMatcher):
    """로컬 테스트용. 파일명 힌트로 결과를 정한다."""

    def detect_face_count(self, image: bytes, *, hint: str = "") -> int:
        name = (hint or "").lower()
        if "noface" in name:
            return 0
        if "twofaces" in name:
            return 2
        return 1

    def compare_faces(
        self, source: bytes, target: bytes, *, hint: str = "", threshold: float = 90.0
    ) -> FaceComparison:
        count = self.detect_face_count(target, hint=hint)
        if count != 1:
            return FaceComparison(face_count=count, similarity=None, matched=False)
        similarity = MISMATCH_SIMILARITY if "mismatch" in (hint or "").lower() else DEFAULT_SIMILARITY
        return FaceComparison(
            face_count=1, similarity=similarity, matched=similarity >= threshold
        )


class RekognitionFaceMatcher(FaceMatcher):
    """AWS 배포용 자리(이번 범위에서는 호출하지 않는다)."""

    def __init__(self, region: str = "ap-northeast-2"):
        self.region = region

    def _not_yet(self):
        raise NotImplementedError("RekognitionFaceMatcher는 AWS 배포 단계에서 구현한다")

    def detect_face_count(self, image: bytes, *, hint: str = "") -> int:
        self._not_yet()

    def compare_faces(
        self, source: bytes, target: bytes, *, hint: str = "", threshold: float = 90.0
    ) -> FaceComparison:
        self._not_yet()


def build_face_matcher(config) -> FaceMatcher:
    """설정에 맞는 FaceMatcher를 만든다."""
    backend = str(config.get("FACE_MATCHER", "fake")).lower()
    if backend == "rekognition":
        return RekognitionFaceMatcher(config.get("AWS_REGION", "ap-northeast-2"))
    return FakeFaceMatcher()


def get_face_matcher() -> FaceMatcher:
    """현재 앱에 붙은 FaceMatcher."""
    return current_app.extensions["face_matcher"]
