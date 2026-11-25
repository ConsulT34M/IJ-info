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

인증 화면을 거래소가 직접 만드는 경우(IA-21·22, D87):
    python tools/fake_exchange.py direct \
      --name 홍길동 --rrn 9001011234567 --issue-date 2015-03-02 --ci <88자> \
      --id-card samples/images/id_card.png --face samples/images/selfie.png
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import pathlib
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


# --- IA-21 / IA-22 거래소가 화면을 만드는 경우 ---------------------------------


def post_signed(args, path: str, payload: dict):
    """서명을 붙여 JSON을 보낸다. 이미지도 이 본문에 base64로 들어간다."""
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return requests.post(
        f"{args.base_url.rstrip('/')}{path}",
        data=body,
        headers=signed_headers(args.api_key, args.hmac_secret, body),
        timeout=30,
    )


def read_image(path: str) -> tuple[str, str]:
    """파일을 base64 문자열과 파일명으로 바꾼다. 파일명은 확장자 확인용이다."""
    file_path = pathlib.Path(path)
    data = file_path.read_bytes()
    return base64.b64encode(data).decode("ascii"), file_path.name


def cmd_direct(args: argparse.Namespace) -> int:
    """IA-01(DIRECT) → IA-21 → IA-22 를 순서대로 호출한다.

    실제 거래소라면 이 세 호출 사이에 자기 화면에서 이용자 입력을 받는다.
    여기서는 명령행 인자로 한 번에 받아 흐름만 보여준다.
    """
    created = post_signed(
        args, "/api/v1/verifications", {"client_user_ref": args.client_user_ref, "mode": "DIRECT"}
    )
    print(f"[IA-01] HTTP {created.status_code}")
    _print_json(created)
    if created.status_code not in (200, 201):
        return 1
    verification_id = created.json()["verification_id"]

    image, filename = read_image(args.id_card)
    submitted = post_signed(
        args,
        f"/api/v1/verifications/{verification_id}/id-card",
        {
            "name": args.name,
            "rrn": args.rrn,
            "issue_date": args.issue_date,
            "ci": args.ci,
            "filename": filename,
            "image": image,
            # 동의는 거래소 화면에서 받고, 받은 사실만 넘긴다(선택)
            "consents": [
                {"type": kind, "version": "v1.0"}
                for kind in ("collect", "uid", "carrier_terms", "biometric")
            ],
        },
    )
    print(f"\n[IA-21 신분증] HTTP {submitted.status_code}")
    _print_json(submitted)
    if submitted.status_code != 200:
        return 1
    if submitted.json().get("status") == "FAILED":
        return 1  # X01 등으로 그 자리에서 종결됐다

    image, filename = read_image(args.face)
    final = post_signed(
        args,
        f"/api/v1/verifications/{verification_id}/face",
        {"filename": filename, "image": image},
    )
    print(f"\n[IA-22 얼굴] HTTP {final.status_code}")
    _print_json(final)
    if final.status_code != 200:
        return 1

    body = final.json()
    print(f"\n판정: {body['status']} ({body['reason_code']})")
    print("결과 웹훅도 callback_url로 한 번 더 간다. serve 터미널에서 확인한다.")
    return 0 if body["status"] == "SUCCEEDED" else 1


# --- IA-11 웹훅 수신 ----------------------------------------------------------


def make_callback_handler(secret: str, path: str):
    class CallbackHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):  # noqa: N802
            """인증창이 돌려보낸 return_url. 실제 거래소라면 여기서 결과 화면을 보여준다."""
            page = (
                "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
                "<title>거래소로 돌아왔다</title></head><body>"
                "<h1>인증창에서 돌아왔다</h1>"
                "<p>판정 결과는 웹훅을 받는 터미널에서 확인한다.</p>"
                "<p>(가짜 거래소 스크립트의 return_url 자리다. 실제 거래소는 "
                "여기서 자체 결과 화면을 보여준다.)</p>"
                "</body></html>"
            ).encode("utf-8")
            print(f"\n[return_url] 이용자가 {self.path} 로 돌아왔다", flush=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

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
    # 브라우저가 return_url로 연결을 열어 둔 사이에도 웹훅을 받아야 하므로 스레드 서버를 쓴다
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port), make_callback_handler(args.hmac_secret, args.path)
    )
    server.daemon_threads = True
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
    parser = argparse.ArgumentParser(
        description="가짜 거래소: IA-01 요청 / 직접 제출(IA-21·22) / 웹훅 수신 / IA-12 조회"
    )
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

    direct_parser = sub.add_parser(
        "direct", help="IA-01(DIRECT) → IA-21 → IA-22. 거래소가 화면을 직접 만드는 경우"
    )
    direct_parser.add_argument("--client-user-ref", default="user-0001")
    direct_parser.add_argument("--name", required=True)
    direct_parser.add_argument("--rrn", required=True, help="하이픈 없는 13자리")
    direct_parser.add_argument("--issue-date", required=True, help="YYYY-MM-DD")
    direct_parser.add_argument(
        "--ci", required=True, help="거래소가 휴대폰 본인확인에서 받은 88자 CI"
    )
    direct_parser.add_argument("--id-card", required=True, help="신분증 이미지 파일")
    direct_parser.add_argument("--face", required=True, help="얼굴 이미지 파일")
    direct_parser.set_defaults(func=cmd_direct)

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
