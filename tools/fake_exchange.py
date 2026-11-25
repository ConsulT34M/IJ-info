#!/usr/bin/env python3
"""가짜 거래소 (위탁사) 스크립트.

이 파일은 **거래소 담당에게 서명 구현 예시로 그대로 넘기는 것**이 목적이다.
그래서 A사 코드를 import하지 않고 표준 라이브러리 + requests만 쓴다.

서명 규칙 (A사와 공유):
    X-Api-Key    발급받은 API Key
    X-Timestamp  유닉스 초 문자열 (현재 시각 ±5분)
    X-Signature  hex(HMAC-SHA256(key=HMAC Secret, msg=X-Timestamp 바이트 + 원본 본문 바이트))
    - 구분자 없음, 소문자 hex, 본문 없는 GET은 빈 바이트
    - HMAC 키는 Secret 문자열의 UTF-8 바이트를 그대로 쓴다

사용법:
    export EKYC_API_KEY=...        # flask create-client가 출력한 값
    export EKYC_HMAC_SECRET=...
    python tools/fake_exchange.py request --client-user-ref user-0001
    python tools/fake_exchange.py serve                 # 웹훅 수신 (별도 터미널)
    python tools/fake_exchange.py query <verification_id>
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

DEFAULT_BASE_URL = os.environ.get("EKYC_BASE_URL", "http://127.0.0.1:8000")
DEFAULT_CALLBACK_PORT = 9000
DEFAULT_CALLBACK_PATH = "/callback"
TIMESTAMP_TOLERANCE_SECONDS = 300


# --- 서명 (거래소가 구현해야 하는 부분) ---------------------------------------


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """X-Signature 값을 만든다."""
    message = timestamp.encode("ascii") + (body or b"")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def signed_headers(api_key: str, secret: str, body: bytes) -> dict[str, str]:
    """요청 헤더 3종을 만든다."""
    timestamp = str(int(time.time()))
    return {
        "X-Api-Key": api_key,
        "X-Timestamp": timestamp,
        "X-Signature": sign(secret, timestamp, body),
        "Content-Type": "application/json",
    }


def signature_is_valid(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    """A사가 보낸 웹훅 서명을 검증한다."""
    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > TIMESTAMP_TOLERANCE_SECONDS:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), (signature or "").lower())


# --- IA-01 인증 요청 ----------------------------------------------------------


def cmd_request(args: argparse.Namespace) -> int:
    payload = {
        "client_user_ref": args.client_user_ref,
        "return_url": args.return_url,
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    url = f"{args.base_url.rstrip('/')}/api/v1/verifications"

    response = requests.post(
        url, data=body, headers=signed_headers(args.api_key, args.hmac_secret, body), timeout=10
    )
    print(f"HTTP {response.status_code}  ({'새 건' if response.status_code == 201 else '기존 건'})")
    _print_json(response)

    if response.status_code in (200, 201):
        data = response.json()
        print("\n아래 주소를 브라우저에서 연다(10분·1회용):")
        print(f"  {data['auth_url']}")
    return 0 if response.status_code in (200, 201) else 1


# --- IA-11 웹훅 수신 ----------------------------------------------------------


def make_callback_handler(secret: str, path: str):
    class CallbackHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):  # noqa: N802  (BaseHTTPRequestHandler 규약)
            if self.path != path:
                self._respond(404, {"error": "not found"})
                return

            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            timestamp = self.headers.get("X-Timestamp", "")
            signature = self.headers.get("X-Signature", "")

            if not signature_is_valid(secret, timestamp, body, signature):
                print("\n[웹훅] 서명 검증 실패 → 401로 거부했다", flush=True)
                self._respond(401, {"error": "bad signature"})
                return

            print("\n[웹훅] 서명 검증 성공", flush=True)
            try:
                print(
                    json.dumps(json.loads(body.decode("utf-8")), ensure_ascii=False, indent=2),
                    flush=True,
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                print(f"  (JSON이 아닌 본문 {len(body)}바이트)", flush=True)
            self._respond(200, {"received": True})

        def log_message(self, *_args):
            return  # 기본 액세스 로그는 끈다

        def _respond(self, status: int, payload: dict):
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return CallbackHandler


def cmd_serve(args: argparse.Namespace) -> int:
    server = HTTPServer(("127.0.0.1", args.port), make_callback_handler(args.hmac_secret, args.path))
    print(f"웹훅 수신 대기: http://127.0.0.1:{args.port}{args.path}  (Ctrl+C로 종료)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료한다.")
    finally:
        server.server_close()
    return 0


# --- IA-12 결과 조회 ----------------------------------------------------------


def cmd_query(args: argparse.Namespace) -> int:
    url = f"{args.base_url.rstrip('/')}/api/v1/verifications/{args.verification_id}"
    # 본문 없는 GET은 빈 바이트에 서명한다
    response = requests.get(
        url, headers=signed_headers(args.api_key, args.hmac_secret, b""), timeout=10
    )
    print(f"HTTP {response.status_code}")
    _print_json(response)
    return 0 if response.status_code == 200 else 1


def _print_json(response: requests.Response) -> None:
    try:
        print(json.dumps(response.json(), ensure_ascii=False, indent=2))
    except json.JSONDecodeError:
        print(response.text[:500])


# --- CLI ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="가짜 거래소: IA-01 요청 / 웹훅 수신 / IA-12 조회")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"A사 주소 (기본 {DEFAULT_BASE_URL})")
    parser.add_argument("--api-key", default=os.environ.get("EKYC_API_KEY", ""))
    parser.add_argument("--hmac-secret", default=os.environ.get("EKYC_HMAC_SECRET", ""))

    sub = parser.add_subparsers(dest="command", required=True)

    request_parser = sub.add_parser("request", help="IA-01 인증 요청")
    request_parser.add_argument("--client-user-ref", default="user-0001")
    request_parser.add_argument(
        "--return-url",
        default=f"http://127.0.0.1:{DEFAULT_CALLBACK_PORT}/done",
        help="callback_url과 같은 origin이어야 한다(D5)",
    )
    request_parser.set_defaults(func=cmd_request)

    serve_parser = sub.add_parser("serve", help="IA-11 웹훅 수신·서명 검증")
    serve_parser.add_argument("--port", type=int, default=DEFAULT_CALLBACK_PORT)
    serve_parser.add_argument("--path", default=DEFAULT_CALLBACK_PATH)
    serve_parser.set_defaults(func=cmd_serve)

    query_parser = sub.add_parser("query", help="IA-12 결과 조회")
    query_parser.add_argument("verification_id")
    query_parser.set_defaults(func=cmd_query)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.hmac_secret:
        print("EKYC_HMAC_SECRET(또는 --hmac-secret)이 필요하다.", file=sys.stderr)
        return 2
    if args.command != "serve" and not args.api_key:
        print("EKYC_API_KEY(또는 --api-key)가 필요하다.", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
