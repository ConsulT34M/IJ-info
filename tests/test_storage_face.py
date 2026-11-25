"""Storage·FaceMatcher 인터페이스와 업로드 검사."""

import io

import pytest

from app.common.face import (
    DEFAULT_SIMILARITY,
    MISMATCH_SIMILARITY,
    FakeFaceMatcher,
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


def test_rekognition_matcher_is_interface_only():
    matcher = RekognitionFaceMatcher()
    with pytest.raises(NotImplementedError):
        matcher.detect_face_count(b"x")
    with pytest.raises(NotImplementedError):
        matcher.compare_faces(b"a", b"b")


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
