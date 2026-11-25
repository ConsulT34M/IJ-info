"""동시 제출: 성공이 한 번만 일어나는지 실제 병렬 HTTP 요청으로 확인한다.

8장의 "원자적 UPDATE(조건부)로 성공 1회만" 요구사항을 검증한다.
PostgreSQL에서만 의미가 있어 postgres 마커를 붙였다(SQLite로 돌리면 skip).

    TEST_DATABASE_URL=postgresql+psycopg://ekyc:ekyc@127.0.0.1:5432/ekyc_test \\
      .venv/bin/python -m pytest tests/test_concurrency.py -q
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from app.common.crypto import sha256_hex
from app.common.phone import code_mac
from app.models import PhoneOtp, PhoneVerification, Verification, db

pytestmark = pytest.mark.postgres

PARALLEL = 8
TIMEOUT = 15


@pytest.fixture
def person(seeded):
    return seeded[0]


def run_parallel(call, count: int = PARALLEL) -> Counter:
    """같은 요청을 동시에 보내고 상태 코드 분포를 돌려준다."""
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(call, index) for index in range(count)]
        return Counter(future.result() for future in futures)


def test_entry_token_is_used_once(app, live_server, api_post):
    """인증창 토큰: 동시에 열어도 한 번만 들어갈 수 있다(410 Gone)."""
    body = api_post(
        "/api/v1/verifications",
        {"client_user_ref": "user-parallel-1", "return_url": "http://127.0.0.1:9000/done"},
    ).get_json()
    token = body["auth_url"].rsplit("/", 1)[-1]
    url = f"{live_server(app)}/verify/start/{token}"

    results = run_parallel(
        lambda _: requests.get(url, allow_redirects=False, timeout=TIMEOUT).status_code
    )

    assert results[302] == 1, results
    assert results[410] == PARALLEL - 1, results

    db.session.expire_all()
    verification = db.session.get(Verification, body["verification_id"])
    assert verification.token_used_at is not None
    assert verification.stage == "CONSENT" and verification.status == "PENDING"


def test_otp_confirm_succeeds_once(app, live_server, flow, carrier_backend, client, person):
    """인증번호: 같은 코드를 동시에 넣어도 한 번만 통과하고 CI도 한 번만 받는다."""
    verification_id = flow.to_phone()
    assert flow.request_otp(person["name"], person["phone_number"]).status_code == 200
    code = flow.inbox_code(person["inbox_key"])
    assert code is not None

    base = live_server(app)
    cookies = {"ekyc_session": client.get_cookie("ekyc_session").value}
    payload = {"code": code, "csrf_token": flow.csrf_token}

    results = run_parallel(
        lambda _: requests.post(
            f"{base}/verify/phone/confirm",
            data=payload,
            cookies=cookies,
            allow_redirects=False,
            timeout=TIMEOUT,
        ).status_code
    )

    # D88: 맞는 번호를 동시에 보낸 것이므로 진 쪽을 '틀린 번호'로 세면 안 된다.
    # 진 쪽도 302로 현재 단계에 돌아간다(먼저 올라갔으면 403). "성공 1회"는
    # 상태 코드가 아니라 아래 증적(OTP_VERIFIED·CI_ISSUED·MC-02 호출)으로 확인한다.
    assert set(results) <= {302, 403}, results
    assert results.get(302, 0) >= 1, results
    assert sum(results.values()) == PARALLEL

    db.session.expire_all()
    verification = db.session.get(Verification, verification_id)
    assert verification.stage == "ID_CARD" and verification.status == "PENDING"

    phone = db.session.get(PhoneVerification, verification_id)
    assert phone.status == "PASSED" and len(phone.ci) == 88
    assert phone.match_token_enc is None
    # D88: 맞는 번호였으므로 시도 횟수가 한 번도 깎이지 않아야 한다.
    # 예전에는 여기서 3이 되어 맞는 번호인데도 P02로 종결됐다.
    assert phone.otp_attempts == 0

    otp = db.session.get(PhoneOtp, verification_id)
    assert otp.code_mac is None and otp.inbox_ciphertext is None

    # 통신사 CI 발급(MC-02)도 한 번만 불렀다
    ci_calls = [call for call in carrier_backend if call["url"].endswith("/ci-issuances")]
    assert len(ci_calls) == 1

    events = [row.event_kind for row in verification.events]
    assert events.count("OTP_VERIFIED") == 1 and events.count("CI_ISSUED") == 1


def test_match_token_is_used_once(carrier_app, live_server, dev_secrets, person):
    """대조 토큰: 동시에 CI 발급을 요청해도 한 번만 성공한다(409 Conflict)."""
    from app.common import secrets as secrets_mod
    from carrier.models import MatchSession, db as carrier_db

    base = live_server(carrier_app)
    headers = {"X-Carrier-Client-Key": secrets_mod.get_secret("ekyc/phone/carrier-client-key")}
    verification_id = "11111111-2222-3333-4444-555555555555"

    matched = requests.post(
        f"{base}/carrier/v1/identity-matches",
        json={
            "verification_id": verification_id,
            "name": person["name"],
            "phone_number": person["phone_number"],
        },
        headers=headers,
        timeout=TIMEOUT,
    ).json()
    token = matched["match_token"]

    results = run_parallel(
        lambda _: requests.post(
            f"{base}/carrier/v1/ci-issuances",
            json={"verification_id": verification_id, "match_token": token},
            headers=headers,
            timeout=TIMEOUT,
        ).status_code
    )

    assert results[200] == 1, results
    assert results[409] == PARALLEL - 1, results

    with carrier_app.app_context():
        session_row = carrier_db.session.get(MatchSession, sha256_hex(token))
        assert session_row.used_at is not None


def test_cancel_and_confirm_race_closes_once(app, live_server, flow, carrier_backend, client, person):
    """취소와 인증번호 확인이 동시에 들어와도 종결은 한 번만 일어난다."""
    verification_id = flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    code = flow.inbox_code(person["inbox_key"])

    base = live_server(app)
    cookies = {"ekyc_session": client.get_cookie("ekyc_session").value}
    csrf = flow.csrf_token

    def _call(index: int) -> str:
        path, data = (
            ("/verify/cancel", {"csrf_token": csrf})
            if index % 2
            else ("/verify/phone/confirm", {"code": code, "csrf_token": csrf})
        )
        response = requests.post(
            f"{base}{path}", data=data, cookies=cookies, allow_redirects=False, timeout=TIMEOUT
        )
        return f"{path}:{response.status_code}"

    results = run_parallel(_call, count=4)

    db.session.expire_all()
    verification = db.session.get(Verification, verification_id)
    # 둘 중 하나만 이기고, 그 결과로 한 번만 종결된다
    assert verification.status in ("CANCELLED", "PENDING"), results
    if verification.status == "CANCELLED":
        assert verification.reason_code == "P04"
    assert len(verification.callbacks) <= 1
