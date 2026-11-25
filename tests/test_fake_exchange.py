"""가짜 거래소 스크립트가 A사와 같은 서명을 만드는지 본다.

이 파일이 깨지면 거래소에 넘긴 예시와 A사 구현이 갈라진 것이다.
"""

import threading
import time
from http.server import ThreadingHTTPServer

import requests

from tools.fake_exchange import make_callback_handler, sign, signature_is_valid, signed_headers

from app.common.hmac_auth import build_signature, verify_signature


def test_tool_and_app_produce_the_same_signature():
    for secret, timestamp, body in [
        ("test-secret", "1700000000", b'{"client_user_ref":"u-1"}'),
        ("test-secret", "1700000000", b""),
        ("다른-시크릿", "1764000000", '{"name":"홍길동"}'.encode("utf-8")),
    ]:
        assert sign(secret, timestamp, body) == build_signature(secret, timestamp, body)


def test_app_accepts_headers_built_by_the_tool():
    body = b'{"client_user_ref":"u-1"}'
    headers = signed_headers("key", "s3cret", body)
    assert headers["X-Api-Key"] == "key"
    assert verify_signature("s3cret", headers["X-Timestamp"], body, headers["X-Signature"])


def test_tool_verifies_webhook_signatures_from_the_app():
    body = b'{"product":"ONBOARDING"}'
    timestamp = str(int(time.time()))
    signature = build_signature("s3cret", timestamp, body)
    assert signature_is_valid("s3cret", timestamp, body, signature) is True
    assert signature_is_valid("s3cret", timestamp, body + b" ", signature) is False
    assert signature_is_valid("other", timestamp, body, signature) is False
    assert signature_is_valid("s3cret", str(int(time.time()) - 301), body, signature) is False
    assert signature_is_valid("s3cret", "not-a-number", body, signature) is False


def test_return_url_page_is_served():
    """이용자가 돌아오는 return_url에 안내 페이지를 돌려준다(501이 아니다)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_callback_handler("s3cret", "/callback"))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = requests.get(
            f"http://127.0.0.1:{server.server_port}/done",
            timeout=5,
            headers={"Connection": "close"},
        )
        assert response.status_code == 200
        assert "인증창에서 돌아왔다" in response.text
        assert response.headers["Content-Type"].startswith("text/html")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
