"""접속 IP 읽기 (TRUST_PROXY)."""

from app.common.client_ip import client_ip


def test_remote_addr_by_default(app):
    with app.test_request_context(environ_base={"REMOTE_ADDR": "203.0.113.9"}):
        assert client_ip() == "203.0.113.9"


def test_x_real_ip_is_ignored_without_trust_proxy(app):
    assert app.config["TRUST_PROXY"] is False
    with app.test_request_context(
        headers={"X-Real-IP": "198.51.100.1"}, environ_base={"REMOTE_ADDR": "203.0.113.9"}
    ):
        assert client_ip() == "203.0.113.9"


def test_x_real_ip_is_used_with_trust_proxy(app):
    app.config["TRUST_PROXY"] = True
    with app.test_request_context(
        headers={"X-Real-IP": "198.51.100.1"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}
    ):
        assert client_ip() == "198.51.100.1"


def test_x_forwarded_for_is_never_used(app):
    app.config["TRUST_PROXY"] = True
    with app.test_request_context(
        headers={"X-Forwarded-For": "198.51.100.1"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}
    ):
        assert client_ip() == "127.0.0.1"
