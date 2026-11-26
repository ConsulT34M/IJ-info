"""Storage·FaceMatcher 인터페이스와 업로드 검사."""

import io

import pytest

from app.common.face import (
    DEFAULT_SIMILARITY,
    MISMATCH_SIMILARITY,
    FakeFaceMatcher,
    LocalFaceMatcher,
    RekognitionFaceMatcher,
    build_face_matcher,
    get_face_matcher,
)
from app.common.storage import (
    LocalStorage,
    S3Storage,
    Storage,
    StorageError,
    build_storage,
    get_storage,
)
from app.common.upload import validate_image_upload
from tests.conftest import sample_jpg, sample_png


class _Upload:
    """werkzeug FileStorage 흉내."""

    def __init__(self, filename: str, data: bytes):
        self.filename = filename
        self._stream = io.BytesIO(data)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)


def test_local_storage_round_trip(tmp_path):
    storage = LocalStorage(tmp_path / "uploads")
    key = storage.save(sample_png(), "png")
    assert key.endswith(".png") and len(key) == 32 + 4
    assert storage.exists(key) is True
    assert storage.load(key) == sample_png()
    assert storage.delete(key) is True
    assert storage.exists(key) is False
    assert storage.delete(key) is False


def test_saved_file_is_owner_only_and_uuid_named(tmp_path):
    storage = LocalStorage(tmp_path / "uploads")
    key = storage.save(sample_jpg(), "jpg")
    path = tmp_path / "uploads" / key
    assert path.exists()
    assert oct(path.stat().st_mode)[-3:] == "600"
    # 원본 파일명은 쓰지 않는다
    assert "id_card" not in key


def test_keys_cannot_escape_the_directory(tmp_path):
    storage = LocalStorage(tmp_path / "uploads")
    for bad in ["../../etc/passwd", "a/b.png", "nope.txt", "", "ABC.png", None]:
        with pytest.raises(StorageError):
            storage.load(bad)
        with pytest.raises(StorageError):
            storage.delete(bad)


def test_unknown_extension_is_rejected(tmp_path):
    storage = LocalStorage(tmp_path / "uploads")
    with pytest.raises(StorageError):
        storage.save(b"x", "svg")


def test_missing_key_raises(tmp_path):
    storage = LocalStorage(tmp_path / "uploads")
    with pytest.raises(StorageError):
        storage.load(Storage.new_key("png"))


def test_s3_storage_is_interface_only():
    storage = S3Storage("bucket")
    for call in [
        lambda: storage.save(b"x", "png"),
        lambda: storage.load("a" * 32 + ".png"),
        lambda: storage.delete("a" * 32 + ".png"),
        lambda: storage.exists("a" * 32 + ".png"),
    ]:
        with pytest.raises(NotImplementedError):
            call()


def test_app_uses_local_storage_and_fake_matcher(app):
    assert isinstance(get_storage(), LocalStorage)
    assert isinstance(get_face_matcher(), FakeFaceMatcher)
    assert str(app.config["UPLOAD_DIR"]).endswith("uploads")


def test_backend_selection(tmp_path):
    local = {"STORAGE_BACKEND": "local", "UPLOAD_DIR": tmp_path}
    assert isinstance(build_storage(local), LocalStorage)
    s3 = {"STORAGE_BACKEND": "s3", "S3_BUCKET": "b", "UPLOAD_DIR": tmp_path}
    assert isinstance(build_storage(s3), S3Storage)
    assert isinstance(build_face_matcher({"FACE_MATCHER": "fake"}), FakeFaceMatcher)
    assert isinstance(build_face_matcher({"FACE_MATCHER": "rekognition"}), RekognitionFaceMatcher)


def test_fake_face_matcher_rules():
    matcher = FakeFaceMatcher()
    assert matcher.detect_face_count(b"x", hint="id_card.png") == 1
    assert matcher.detect_face_count(b"x", hint="noface.png") == 0
    assert matcher.detect_face_count(b"x", hint="twofaces.png") == 2
    assert matcher.detect_face_count(b"x") == 1

    passed = matcher.compare_faces(b"a", b"b", hint="selfie.png", threshold=90)
    assert passed == type(passed)(face_count=1, similarity=DEFAULT_SIMILARITY, matched=True)

    failed = matcher.compare_faces(b"a", b"b", hint="selfie_mismatch.png", threshold=90)
    assert failed.similarity == MISMATCH_SIMILARITY and failed.matched is False

    no_face = matcher.compare_faces(b"a", b"b", hint="noface.png", threshold=90)
    assert no_face.face_count == 0 and no_face.similarity is None and no_face.matched is False

    two = matcher.compare_faces(b"a", b"b", hint="twofaces.png", threshold=90)
    assert two.face_count == 2 and two.matched is False


# ---------------------------------------------------------------- Rekognition
#
# AWS 없이 확인한다. boto3 클라이언트 자리에 가짜를 끼워 **요청 모양과 판정**을 본다.
# 시연 때 실제로 도는 구현이라 여기서 막아 두는 값이 크다(D93).


class _FakeRekognition:
    """boto3 rekognition 클라이언트 흉내."""

    def __init__(self, faces=1, similarity=None, error_code=None):
        self.faces = faces
        self.similarity = similarity
        self.error_code = error_code
        self.calls = []

    def _maybe_raise(self):
        if self.error_code:
            raise _AwsError(self.error_code)

    def detect_faces(self, **kwargs):
        self.calls.append(("detect_faces", kwargs))
        self._maybe_raise()
        return {"FaceDetails": [{"Confidence": 99.9}] * self.faces}

    def compare_faces(self, **kwargs):
        self.calls.append(("compare_faces", kwargs))
        self._maybe_raise()
        if self.similarity is None:
            return {"FaceMatches": [], "UnmatchedFaces": [{}]}
        return {"FaceMatches": [{"Similarity": self.similarity}]}


class _AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def test_rekognition_counts_faces():
    client = _FakeRekognition(faces=2)
    assert RekognitionFaceMatcher(client=client).detect_face_count(b"img") == 2


def test_rekognition_judges_with_our_own_threshold():
    """SimilarityThreshold=0 으로 받아 와서 판정은 우리가 한다(증적에 유사도를 남기려고)."""
    client = _FakeRekognition(similarity=93.5)
    result = RekognitionFaceMatcher(client=client).compare_faces(b"id", b"selfie", threshold=90)

    assert result.matched is True and result.similarity == 93.5
    sent = dict(client.calls[-1][1])
    assert sent["SimilarityThreshold"] == 0
    assert sent["SourceImage"] == {"Bytes": b"id"}
    assert sent["TargetImage"] == {"Bytes": b"selfie"}


def test_rekognition_below_threshold_is_not_a_match():
    client = _FakeRekognition(similarity=71.0)
    result = RekognitionFaceMatcher(client=client).compare_faces(b"id", b"selfie", threshold=90)
    assert result.matched is False and result.similarity == 71.0


def test_rekognition_no_match_reports_zero():
    client = _FakeRekognition(similarity=None)
    result = RekognitionFaceMatcher(client=client).compare_faces(b"id", b"selfie")
    assert result.similarity == 0.0 and result.matched is False


def test_rekognition_counts_zero_faces_for_a_non_image():
    """이미지가 아니면 AWS가 거부한다. 얼굴 0개로 본다(→ E04)."""
    client = _FakeRekognition(error_code="InvalidImageFormatException")
    assert RekognitionFaceMatcher(client=client).detect_face_count(b"dog") == 0


def test_rekognition_two_faces_short_circuits_without_comparing():
    """셀카에 얼굴이 둘이면 대조까지 가지 않는다(E04)."""
    client = _FakeRekognition(faces=2)
    result = RekognitionFaceMatcher(client=client).compare_faces(b"id", b"selfie")
    assert result.face_count == 2 and result.matched is False
    assert [name for name, _ in client.calls] == ["detect_faces"]


def test_rekognition_id_card_without_a_face_is_not_a_match():
    """신분증에서 얼굴을 못 찾으면 CompareFaces가 거부한다. 대조 불가 → 불일치."""

    class _OnlyCompareFails(_FakeRekognition):
        def compare_faces(self, **kwargs):
            raise _AwsError("InvalidParameterException")

    result = RekognitionFaceMatcher(client=_OnlyCompareFails()).compare_faces(b"id", b"selfie")
    assert result.face_count == 1 and result.similarity is None and result.matched is False


def test_rekognition_lets_unexpected_errors_through():
    """권한 오류 같은 건 삼키지 않는다. 조용히 '불일치'로 끝나면 안 된다."""
    client = _FakeRekognition(error_code="AccessDeniedException")
    with pytest.raises(_AwsError):
        RekognitionFaceMatcher(client=client).detect_face_count(b"img")


def test_rekognition_rejects_an_oversized_image():
    big = b"x" * (RekognitionFaceMatcher.MAX_IMAGE_BYTES + 1)
    with pytest.raises(ValueError):
        RekognitionFaceMatcher(client=_FakeRekognition()).detect_face_count(big)


def test_rekognition_ignores_the_filename_hint():
    """파일명을 믿으면 그 자체가 취약점이다. 어떤 힌트를 줘도 결과가 같아야 한다."""
    matcher = RekognitionFaceMatcher(client=_FakeRekognition(similarity=95.0))
    plain = matcher.compare_faces(b"id", b"selfie", threshold=90)
    hinted = matcher.compare_faces(b"id", b"selfie", hint="noface_mismatch.png", threshold=90)
    assert plain == hinted and hinted.matched is True


# ---------------------------------------------------------------- Local(OpenCV)

cv2 = pytest.importorskip("cv2", reason="LocalFaceMatcher는 opencv-python-headless가 필요하다")


def test_local_matcher_finds_no_face_in_a_non_image():
    assert LocalFaceMatcher().detect_face_count(b"definitely not an image") == 0
    assert LocalFaceMatcher().detect_face_count(b"") == 0


def test_local_matcher_finds_no_face_in_the_synthetic_samples():
    """저장소 샘플은 합성 단색 이미지라 얼굴이 없다.

    그래서 FACE_MATCHER=local 로 두면 샘플만으로는 전 건이 E04가 된다.
    local 모드를 쓰려면 **실제 얼굴 사진**이 필요하다(D93).
    """
    assert LocalFaceMatcher().detect_face_count(sample_png()) == 0


def test_local_matcher_ignores_the_filename_hint():
    matcher = LocalFaceMatcher()
    data = sample_png()
    assert matcher.detect_face_count(data, hint="selfie.png") == matcher.detect_face_count(
        data, hint="noface.png"
    )


def test_local_matcher_reports_no_match_when_there_is_no_face():
    result = LocalFaceMatcher().compare_faces(sample_png(), sample_png(), threshold=90)
    assert result.face_count == 0 and result.similarity is None and result.matched is False


def test_upload_accepts_png_and_jpg():
    png = validate_image_upload(
        _Upload("id_card.png", sample_png()), max_bytes=1000, allowed_extensions=("jpg", "png")
    )
    assert png.ok and png.extension == "png" and png.hint == "id_card.png"

    jpg = validate_image_upload(
        _Upload("id_card.JPG", sample_jpg()), max_bytes=1000, allowed_extensions=("jpg", "png")
    )
    assert jpg.ok and jpg.extension == "jpg"


def test_upload_rejects_extension_size_magic_and_empty():
    def check(filename, data, max_bytes=1000):
        return validate_image_upload(
            _Upload(filename, data), max_bytes=max_bytes, allowed_extensions=("jpg", "jpeg", "png")
        )

    assert check("x.gif", sample_png()).error == "EXTENSION"
    assert check("x", sample_png()).error == "EXTENSION"
    assert check("x.png", sample_png(), max_bytes=10).error == "SIZE"
    assert check("x.png", b"").error == "EMPTY"
    assert check("x.png", b"not an image at all").error == "MAGIC"
    # 확장자만 바꾼 실행 파일
    assert check("x.png", b"#!/bin/sh\necho hi\n").error == "MAGIC"
    assert validate_image_upload(None, max_bytes=10, allowed_extensions=("png",)).error == "EMPTY"
    assert check("", sample_png()).error == "EMPTY"
