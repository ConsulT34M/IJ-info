"""AES-256-GCM 암복호화와 키 기반 요약."""

import base64

import pytest

from app.common import crypto


def test_round_trip_keeps_value():
    key = crypto.generate_key()
    blob = crypto.encrypt_str(key, "900101-1234568")
    assert crypto.decrypt_str(key, blob) == "900101-1234568"


def test_ciphertext_is_nonce_plus_sealed_and_not_plaintext():
    key = crypto.generate_key()
    blob = crypto.encrypt(key, b"secret-value")
    assert len(blob) == crypto.NONCE_SIZE + len(b"secret-value") + 16
    assert b"secret-value" not in blob


def test_same_plaintext_gives_different_ciphertext():
    key = crypto.generate_key()
    assert crypto.encrypt(key, b"x") != crypto.encrypt(key, b"x")


def test_wrong_key_or_tampering_raises():
    key = crypto.generate_key()
    blob = crypto.encrypt(key, b"x")
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt(crypto.generate_key(), blob)
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt(key, blob[:-1] + bytes([blob[-1] ^ 0x01]))
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt(key, b"short")


def test_aad_must_match():
    key = crypto.generate_key()
    blob = crypto.encrypt(key, b"x", aad=b"verification-1")
    assert crypto.decrypt(key, blob, aad=b"verification-1") == b"x"
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt(key, blob, aad=b"verification-2")


def test_key_encoding_round_trip_and_length_guard():
    key = crypto.generate_key()
    assert crypto.decode_key(crypto.encode_key(key)) == key
    with pytest.raises(ValueError):
        crypto.decode_key(base64.b64encode(b"too-short").decode())
    with pytest.raises(ValueError):
        crypto.decode_key("not-base64!!")


def test_digest_shapes():
    assert len(crypto.hmac_sha256_hex("k", "m")) == 64
    assert len(crypto.hmac_sha512_b64("k", "m")) == 88
    assert len(crypto.sha256_hex("m")) == 64
    assert crypto.hmac_sha256_hex("k", "m") == crypto.hmac_sha256_hex(b"k", b"m")


def test_constant_time_equals_handles_none():
    assert crypto.constant_time_equals("a", "a") is True
    assert crypto.constant_time_equals("a", "b") is False
    assert crypto.constant_time_equals(None, "a") is False
    assert crypto.constant_time_equals("a", None) is False
