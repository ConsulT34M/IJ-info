"""얼굴 검출·대조. 백엔드를 갈아 끼운다: fake | local | rekognition.

    FACE_MATCHER=fake          기본. 파일명 힌트로 결과를 정한다(시연·테스트 전용)
    FACE_MATCHER=local         OpenCV로 **실제 이미지**에서 얼굴을 검출한다(AWS 전까지)
    FACE_MATCHER=rekognition   AWS Rekognition CompareFaces (배포 후)

**fake 외의 구현은 `hint`(원본 파일명)를 절대 보지 않는다.** 실제 서비스가 파일명을
믿고 판정하면 그 자체가 취약점이다. 인터페이스 호환을 위해 인자만 남겨 둔다.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from flask import current_app

DEFAULT_SIMILARITY = 95.0
MISMATCH_SIMILARITY = 40.0

# LocalFaceMatcher가 얼굴 영역을 비교할 때 쓰는 크기
_FACE_SIZE = 112


@dataclass(frozen=True)
class FaceComparison:
    """얼굴 대조 결과. face_checks에 그대로 들어간다.

    face_count는 **셀카(target)** 에서 검출한 얼굴 수다. 1이 아니면 호출부가 E04로 본다.
    similarity가 None이면 "대조하지 못했다"는 뜻이고, 호출부는 불일치로 처리한다.
    """

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
    """시연·테스트 전용. **이미지를 읽지 않고 파일명으로** 결과를 정한다.

    규칙: 파일명에 `noface` → 0개, `twofaces` → 2개, `mismatch` → 유사도 40,
    그 밖에는 얼굴 1개·유사도 95.

    그래서 강아지 사진을 올려도 '동일 인물'로 통과한다. 의도한 동작이지만
    실제 판정이 아니므로, 진단·발표에서는 `local`이나 `rekognition`을 쓴다.
    """

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


class LocalFaceMatcher(FaceMatcher):
    """OpenCV로 **실제 이미지**를 본다. AWS 배포 전까지 쓰는 자리다.

    - **얼굴 검출은 진짜다.** 강아지·풍경 사진은 얼굴 0개로 걸러진다(E04).
      Rekognition으로 바꿔도 이 동작은 같다.
    - **유사도는 근사치고, 점수 체계가 Rekognition과 다르다.** 얼굴 영역을 잘라
      정규화한 뒤 상관계수로 점수를 낸다. 임베딩이 아니라서 사람을 가리는 정확도는
      Rekognition보다 많이 떨어진다. 실제 샘플 한 쌍(같은 사람)에서 84.6이 나와,
      운영 임계값 90을 그대로 쓰면 본인인데도 불일치가 된다. 그래서 **`FACE_LOCAL_THRESHOLD`
      로 임계값을 따로 둔다**(기본 80). 샘플 한 쌍으로 맞춘 값이니 자기 사진으로 확인하고
      조정한다. 본인/타인 판별은 배포 후 Rekognition에 맡긴다.
    - `hint`(파일명)는 보지 않는다.

    `opencv-python-headless`가 필요하다. 없으면 기동 시점이 아니라
    **첫 호출에서** 분명한 메시지로 실패한다.
    """

    def __init__(
        self,
        min_neighbors: int = 8,
        scale_factor: float = 1.1,
        min_size_ratio: float = 0.10,
        threshold: float | None = None,
    ):
        # min_size_ratio: 짧은 변의 몇 %보다 작은 후보는 버린다.
        # 고정 픽셀로 두면 고해상도 신분증에서 글자·무늬를 얼굴로 오탐한다
        # (실제 샘플에서 3개가 잡혔다). 비율로 두면 1개로 떨어진다(D93).
        self.min_neighbors = min_neighbors
        self.scale_factor = scale_factor
        self.min_size_ratio = min_size_ratio
        # Rekognition과 점수 체계가 달라 임계값을 따로 둔다. None이면 호출부 값을 쓴다.
        self.threshold = threshold
        self._cv2 = None
        self._cascade = None

    # --- OpenCV 준비 -------------------------------------------------
    def _load(self):
        if self._cv2 is not None:
            return self._cv2, self._cascade
        try:
            import cv2  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - 설치 환경에 따라 다름
            raise RuntimeError(
                "LocalFaceMatcher에는 OpenCV가 필요하다. "
                "`uv pip install opencv-python-headless` 로 설치하거나 FACE_MATCHER=fake 로 둔다."
            ) from exc

        # OpenCV 5부터 CascadeClassifier가 기본 네임스페이스에서 빠졌다.
        # 모델 파일을 따로 받지 않아도 되는 4.x를 쓴다.
        if not hasattr(cv2, "CascadeClassifier"):  # pragma: no cover - 버전에 따라 다름
            raise RuntimeError(
                f"OpenCV {cv2.__version__}에는 CascadeClassifier가 없다. "
                "`uv pip install 'opencv-python-headless>=4.8,<5'` 로 맞춘다."
            )
        path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        cascade = cv2.CascadeClassifier(path)
        if cascade.empty():  # pragma: no cover - 설치가 깨진 경우
            raise RuntimeError(f"얼굴 검출기를 읽지 못했다: {path}")
        self._cv2, self._cascade = cv2, cascade
        return cv2, cascade

    def _decode_gray(self, image: bytes):
        """바이트를 흑백 이미지로. 이미지가 아니면 None."""
        cv2, _ = self._load()
        import numpy as np  # noqa: PLC0415

        buffer = np.frombuffer(image, dtype=np.uint8)
        if buffer.size == 0:
            return None
        decoded = cv2.imdecode(buffer, cv2.IMREAD_GRAYSCALE)
        return decoded

    def _faces(self, image: bytes):
        """검출된 얼굴 사각형 목록. 이미지가 아니면 빈 목록."""
        cv2, cascade = self._load()
        gray = self._decode_gray(image)
        if gray is None:
            return []
        gray = cv2.equalizeHist(gray)
        side = int(min(gray.shape[:2]) * self.min_size_ratio)
        side = max(side, 24)
        found = cascade.detectMultiScale(
            gray,
            scaleFactor=self.scale_factor,
            minNeighbors=self.min_neighbors,
            minSize=(side, side),
        )
        return list(found)

    def _largest_face_crop(self, image: bytes):
        """가장 큰 얼굴을 잘라 정규화한다. 얼굴이 없으면 None."""
        cv2, _ = self._load()
        faces = self._faces(image)
        if not faces:
            return None
        x, y, w, h = max(faces, key=lambda r: int(r[2]) * int(r[3]))
        gray = cv2.equalizeHist(self._decode_gray(image))
        crop = gray[y : y + h, x : x + w]
        return cv2.equalizeHist(cv2.resize(crop, (_FACE_SIZE, _FACE_SIZE)))

    # --- 인터페이스 ---------------------------------------------------
    def detect_face_count(self, image: bytes, *, hint: str = "") -> int:
        return len(self._faces(image))

    def compare_faces(
        self, source: bytes, target: bytes, *, hint: str = "", threshold: float = 90.0
    ) -> FaceComparison:
        count = self.detect_face_count(target)
        if count != 1:
            return FaceComparison(face_count=count, similarity=None, matched=False)

        source_face = self._largest_face_crop(source)
        target_face = self._largest_face_crop(target)
        if source_face is None or target_face is None:
            # 신분증에서 얼굴을 못 찾으면 대조 자체가 성립하지 않는다.
            return FaceComparison(face_count=count, similarity=None, matched=False)

        similarity = self._similarity(source_face, target_face)
        cutoff = self.threshold if self.threshold is not None else threshold
        return FaceComparison(
            face_count=1, similarity=similarity, matched=similarity >= cutoff
        )

    def _similarity(self, left, right) -> float:
        """0~100 근사 유사도. 상관계수와 히스토그램 상관을 섞는다."""
        cv2, _ = self._load()
        correlation = float(cv2.matchTemplate(left, right, cv2.TM_CCOEFF_NORMED)[0][0])
        left_hist = cv2.calcHist([left], [0], None, [64], [0, 256])
        right_hist = cv2.calcHist([right], [0], None, [64], [0, 256])
        cv2.normalize(left_hist, left_hist)
        cv2.normalize(right_hist, right_hist)
        histogram = float(cv2.compareHist(left_hist, right_hist, cv2.HISTCMP_CORREL))
        blended = 0.7 * correlation + 0.3 * histogram
        return round(max(0.0, min(1.0, (blended + 1) / 2)) * 100, 2)


class RekognitionFaceMatcher(FaceMatcher):
    """AWS Rekognition. 배포 후 쓰는 구현이다.

    - `DetectFaces`로 얼굴 수를 센다.
    - `CompareFaces`로 신분증 사진과 셀카를 대조한다. `SimilarityThreshold`를 0으로
      주고 **판정은 우리 쪽 threshold로** 한다. 그래야 유사도를 증적(`face_checks`)에
      남길 수 있다.
    - 신분증에서 얼굴을 못 찾으면 Rekognition이 `InvalidParameterException`을 낸다.
      대조 불가로 보고 불일치 처리한다.
    - `hint`(파일명)는 보지 않는다.

    `boto3`가 필요하다. 자격증명은 EC2 인스턴스의 IAM 역할에서 온다
    (키를 코드·환경변수에 두지 않는다).
    """

    MAX_IMAGE_BYTES = 5 * 1024 * 1024  # Rekognition 직접 전달 상한

    def __init__(self, region: str = "ap-northeast-2", client=None):
        self.region = region
        self._client = client

    @property
    def client(self):
        if self._client is None:
            try:
                import boto3  # noqa: PLC0415
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "RekognitionFaceMatcher에는 boto3가 필요하다. `uv pip install boto3`."
                ) from exc
            self._client = boto3.client("rekognition", region_name=self.region)
        return self._client

    def _check_size(self, image: bytes) -> None:
        if len(image) > self.MAX_IMAGE_BYTES:
            raise ValueError("Rekognition에 바로 넘길 수 있는 크기를 넘었다(5MB).")

    def detect_face_count(self, image: bytes, *, hint: str = "") -> int:
        self._check_size(image)
        try:
            response = self.client.detect_faces(
                Image={"Bytes": image}, Attributes=["DEFAULT"]
            )
        except Exception as exc:  # noqa: BLE001 - 어떤 오류든 '검출 실패'로 본다
            if self._is_invalid_image(exc):
                return 0
            raise
        return len(response.get("FaceDetails", []))

    def compare_faces(
        self, source: bytes, target: bytes, *, hint: str = "", threshold: float = 90.0
    ) -> FaceComparison:
        self._check_size(source)
        self._check_size(target)

        count = self.detect_face_count(target)
        if count != 1:
            return FaceComparison(face_count=count, similarity=None, matched=False)

        try:
            response = self.client.compare_faces(
                SourceImage={"Bytes": source},
                TargetImage={"Bytes": target},
                # 0으로 두고 판정은 우리가 한다. 유사도를 증적으로 남기기 위해서다.
                SimilarityThreshold=0,
            )
        except Exception as exc:  # noqa: BLE001
            if self._is_invalid_image(exc):
                # 신분증에서 얼굴을 못 찾은 경우다. 대조 불가 → 불일치.
                return FaceComparison(face_count=count, similarity=None, matched=False)
            raise

        matches = response.get("FaceMatches") or []
        if not matches:
            return FaceComparison(face_count=count, similarity=0.0, matched=False)

        similarity = round(float(max(m["Similarity"] for m in matches)), 2)
        return FaceComparison(
            face_count=count, similarity=similarity, matched=similarity >= threshold
        )

    @staticmethod
    def _is_invalid_image(exc: Exception) -> bool:
        """얼굴을 못 찾았거나 이미지가 아닌 경우인지."""
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        return code in {
            "InvalidParameterException",
            "InvalidImageFormatException",
            "ImageTooLargeException",
        }


BACKENDS = {
    "fake": FakeFaceMatcher,
    "local": LocalFaceMatcher,
    "rekognition": RekognitionFaceMatcher,
}


def build_face_matcher(config) -> FaceMatcher:
    """설정에 맞는 FaceMatcher를 만든다. 모르는 값이면 기동 때 바로 알려 준다."""
    backend = str(config.get("FACE_MATCHER", "fake")).lower()
    if backend not in BACKENDS:
        raise ValueError(
            f"FACE_MATCHER 값이 올바르지 않다: {backend!r} (가능한 값: {', '.join(BACKENDS)})"
        )
    if backend == "rekognition":
        return RekognitionFaceMatcher(config.get("AWS_REGION", "ap-northeast-2"))
    if backend == "local":
        return LocalFaceMatcher(threshold=config.get("FACE_LOCAL_THRESHOLD", 80))
    return BACKENDS[backend]()


def get_face_matcher() -> FaceMatcher:
    """현재 앱에 붙은 FaceMatcher."""
    return current_app.extensions["face_matcher"]
