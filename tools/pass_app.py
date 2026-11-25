#!/usr/bin/env python3
"""모의 PASS 앱 — 이용자의 휴대폰 역할을 하는 작은 프로그램.

실제 흐름에서는 이용자가 본인 명의 휴대폰을 들고 있고, 거기에 인증번호 문자가 온다.
"휴대폰을 들고 있다"는 사실이 수신함의 열쇠다. 실습에서는 그걸 흉내 낼 수 없어서
people.json의 inbox_key를 복붙해 왔는데, 이 프로그램이 그 자리를 대신한다(D85).

  1. 기기 등록 — 통신사에 명의(성명·생년월일·번호)를 확인받고 수신함 키를 발급받는다.
                 PASS 앱을 깔 때 하는 통신사 명의 인증에 해당한다.
  2. 문자 수신 — 등록된 기기로 그 번호에 온 인증번호를 본다.

A사 코드를 import하지 않는다. 별개의 기기이므로 표준 라이브러리 + requests만 쓴다.

    python tools/pass_app.py                 # 등록돼 있으면 수신 대기, 아니면 등록부터
    python tools/pass_app.py register        # 기기 등록 (물어보면서)
    python tools/pass_app.py register --phone 01012345678 --name 홍길동 --birth 1990-01-01
    python tools/pass_app.py inbox           # 지금 와 있는 인증번호 한 번 보기
    python tools/pass_app.py watch           # 새 문자가 올 때까지 기다리기
    python tools/pass_app.py status          # 등록 상태
    python tools/pass_app.py logout          # 기기 등록 해제
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path

import requests

BASE_URL = os.environ.get("EKYC_BASE_URL", "http://127.0.0.1:8000")
DEVICE_FILE = Path(
    os.environ.get("PASS_DEVICE_FILE", Path(__file__).resolve().parents[1] / "instance" / "pass_device.json")
)
TIMEOUT = 10
POLL_SECONDS = 2

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
JSON_HEADERS = {"Accept": "application/json"}

BOX_WIDTH = 46


# ----------------------------------------------------------------- 화면 출력


def _width(text: str) -> int:
    """한글처럼 두 칸을 차지하는 글자를 세어 상자 너비를 맞춘다.

    `·` 같은 '애매한 너비(Ambiguous)' 글자는 터미널마다 1칸·2칸이 갈려서
    상자 안에서는 쓰지 않는다.
    """
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def _line(text: str = "") -> str:
    pad = max(0, BOX_WIDTH - _width(text))
    return f"│ {text}{' ' * pad} │"


def box(lines: list[str], top: str = "┌", bottom: str = "└") -> str:
    bar = "─" * (BOX_WIDTH + 2)
    body = "\n".join(_line(line) for line in lines)
    return f"{top}{bar}┐\n{body}\n{bottom}{bar}┘"


def show_message(payload: dict) -> None:
    """도착한 문자를 휴대폰 화면처럼 보여준다."""
    code = payload["code"]
    spaced = " ".join(code)
    print()
    print(
        box(
            [
                "[인증정보평가] 본인확인 인증번호",
                "",
                f"        {spaced}",
                "",
                "3분 안에 입력한다.",
                "타인에게 알려주지 않는다.",
                "",
                f"유효 {payload.get('code_expires_at', '-')}",
                f"{payload.get('issue_no', '-')}번째 발송",
            ]
        )
    )
    print()


# ----------------------------------------------------------------- 기기 파일


def load_device() -> dict | None:
    if not DEVICE_FILE.exists():
        return None
    try:
        return json.loads(DEVICE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save_device(device: dict) -> None:
    DEVICE_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEVICE_FILE.write_text(json.dumps(device, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    DEVICE_FILE.chmod(0o600)


# ----------------------------------------------------------------- 서버 호출


def open_session() -> tuple[requests.Session, str]:
    """수신함 화면을 열어 세션 쿠키와 CSRF 토큰을 받는다. 브라우저와 같은 절차다."""
    session = requests.Session()
    try:
        response = session.get(f"{BASE_URL}/test-inbox/", timeout=TIMEOUT)
    except requests.RequestException as exc:
        raise SystemExit(f"A사 앱에 연결할 수 없다: {BASE_URL} ({exc.__class__.__name__})")
    if response.status_code == 403:
        raise SystemExit("수신함 접근이 거부됐다. TEST_INBOX_ALLOWED_IPS를 확인한다.")
    if response.status_code != 200:
        raise SystemExit(f"수신함 화면을 열 수 없다: HTTP {response.status_code}")
    found = CSRF_RE.search(response.text)
    if not found:
        raise SystemExit("CSRF 토큰을 찾지 못했다. A사 앱 버전을 확인한다.")
    return session, found.group(1)


def post(path: str, data: dict) -> tuple[int, dict]:
    session, token = open_session()
    response = session.post(
        f"{BASE_URL}{path}",
        data={**data, "csrf_token": token},
        headers=JSON_HEADERS,
        timeout=TIMEOUT,
    )
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, {"error": f"예상하지 못한 응답이다 (HTTP {response.status_code})"}


# ----------------------------------------------------------------- 명령


def cmd_register(args) -> int:
    phone = args.phone or input("휴대폰번호 (01012345678): ").strip()
    name = args.name or input("성명: ").strip()
    birth = args.birth or input("생년월일 (1990-01-01): ").strip()

    print()
    print("통신사에 명의를 확인하는 중...")
    status, body = post(
        "/test-inbox/devices", {"phone_number": phone, "name": name, "birth_date": birth}
    )
    if status != 200:
        print(f"  기기 등록 실패: {body.get('error', status)}")
        if status == 403:
            print("  (번호·성명·생년월일이 통신사 명부와 모두 맞아야 한다)")
        return 1

    save_device(
        {
            "phone_mask": body["phone_mask"],
            "inbox_key": body["inbox_key"],
            "base_url": BASE_URL,
            "registered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    )
    print(f"  명의 확인됨. 기기를 등록했다. ({body['phone_mask']})")
    print(f"  수신함 키는 {DEVICE_FILE} 에 저장했다 (권한 600).")
    print("  같은 번호로 다시 등록하면 이전 기기는 쓸 수 없다.")
    return 0


def _require_device() -> dict:
    device = load_device()
    if device is None:
        raise SystemExit("등록된 기기가 없다. 먼저 'pass_app.py register'를 실행한다.")
    return device


def fetch_code(device: dict) -> tuple[int, dict]:
    return post("/test-inbox/latest", {"inbox_key": device["inbox_key"]})


def cmd_inbox(args) -> int:
    device = _require_device()
    status, body = fetch_code(device)
    if status == 200:
        show_message(body)
        return 0
    if status == 404 and "수신함" in body.get("error", ""):
        print("기기 등록이 만료됐다. 다시 등록한다. (같은 번호로 다른 기기를 등록했을 수 있다)")
        return 1
    print(f"{device['phone_mask']}: {body.get('error', status)}")
    return 1


def cmd_watch(args) -> int:
    device = _require_device()
    print(
        box(
            [
                f"PASS 모의 앱   {device['phone_mask']}",
                "새 문자를 기다린다. (Ctrl+C로 종료)",
            ]
        )
    )
    seen: tuple | None = None
    try:
        while True:
            status, body = fetch_code(device)
            if status == 200:
                mark = (body["code"], body.get("issue_no"))
                if mark != seen:
                    seen = mark
                    show_message(body)
            elif status == 404 and "수신함" in body.get("error", ""):
                print("기기 등록이 만료됐다. 다시 등록한다.")
                return 1
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n종료한다.")
        return 0


def cmd_status(args) -> int:
    device = load_device()
    if device is None:
        print("등록된 기기가 없다.")
        return 1
    print(
        box(
            [
                "PASS 모의 앱   기기 등록됨",
                f"번호     {device['phone_mask']}",
                f"등록     {device.get('registered_at', '-')}",
                f"서버     {device.get('base_url', '-')}",
            ]
        )
    )
    print(f"수신함 키는 화면에 찍지 않는다. {DEVICE_FILE} 에 있다.")
    return 0


def cmd_logout(args) -> int:
    if DEVICE_FILE.exists():
        DEVICE_FILE.unlink()
        print("기기 등록을 해제했다. 저장된 수신함 키를 지웠다.")
        print("(A사 쪽 수신함 키는 남아 있다. 다시 등록하면 새 키로 바뀐다.)")
        return 0
    print("등록된 기기가 없다.")
    return 1


def cmd_default(args) -> int:
    """인자가 없으면: 등록돼 있으면 수신 대기, 아니면 등록부터."""
    if load_device() is None:
        print(box(["PASS 모의 앱", "등록된 기기가 없다. 명의 인증을 먼저 한다."]))
        print()
        if cmd_register(args) != 0:
            return 1
        print()
    return cmd_watch(args)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="모의 PASS 앱 — 기기 등록과 인증번호 수신",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--phone")
    parser.add_argument("--name")
    parser.add_argument("--birth", help="YYYY-MM-DD")
    sub = parser.add_subparsers(dest="command")

    for name, handler, help_text in [
        ("register", cmd_register, "통신사 명의 확인 후 기기 등록"),
        ("inbox", cmd_inbox, "지금 와 있는 인증번호 한 번 보기"),
        ("watch", cmd_watch, "새 문자가 올 때까지 기다리기"),
        ("status", cmd_status, "등록 상태"),
        ("logout", cmd_logout, "기기 등록 해제"),
    ]:
        child = sub.add_parser(name, help=help_text)
        child.set_defaults(handler=handler)
        if name == "register":
            child.add_argument("--phone")
            child.add_argument("--name")
            child.add_argument("--birth", help="YYYY-MM-DD")

    args = parser.parse_args()
    handler = getattr(args, "handler", cmd_default)
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
