"""모의 PASS 앱 기기 등록(D85).

실습에서 people.json의 inbox_key를 복붙하던 자리를, 통신사 명의 확인(MC-03)을
거쳐 수신함 키를 발급받는 경로로 바꿨다. 여기서는 그 경로가 명의를 제대로
확인하는지와, 새로 등록하면 이전 키가 끊기는지를 본다.

수신함 자체는 D3대로 실습 전용·진단 범위 제외다. 그래도 아무나 남의 번호로
등록하지는 못해야 한다.
"""

from __future__ import annotations

import re

import pytest

from app.common.carrier import CarrierError

DEVICES = "/test-inbox/devices"
LATEST = "/test-inbox/latest"
JSON = {"Accept": "application/json"}


@pytest.fixture
def person(seeded):
    return seeded[0]


@pytest.fixture
def csrf(client):
    """수신함 화면에서 CSRF 토큰을 받아 온다. PASS 앱이 하는 것과 같다."""
    return read_csrf(client)


def read_csrf(client) -> str:
    html = client.get("/test-inbox/").get_data(as_text=True)
    found = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert found
    return found.group(1)


def register(client, csrf, person, **overrides):
    data = {
        "csrf_token": csrf,
        "phone_number": person["phone_number"],
        "name": person["name"],
        "birth_date": person["birth_date"],
    }
    data.update(overrides)
    return client.post(DEVICES, data=data, headers=JSON)


def read_inbox(client, csrf, inbox_key):
    return client.post(
        LATEST, data={"csrf_token": csrf, "inbox_key": inbox_key}, headers=JSON
    )


# ---------------------------------------------------------------- 기기 등록


def test_registration_issues_an_inbox_key(client, csrf, person, carrier_backend):
    response = register(client, csrf, person)
    assert response.status_code == 200
    body = response.get_json()
    assert len(body["inbox_key"]) >= 24
    assert body["phone_mask"].startswith("010-")
    assert person["phone_number"] not in body["phone_mask"]  # 원문은 돌려주지 않는다


def test_registration_asks_the_carrier(client, csrf, person, carrier_backend):
    register(client, csrf, person)
    calls = [call for call in carrier_backend if call["url"].endswith("/device-registrations")]
    assert len(calls) == 1
    assert calls[0]["payload"]["birth_date"] == person["birth_date"]
    # 기기 등록은 대조 토큰을 만들지 않는다(MC-01과 다른 점)
    assert not [c for c in carrier_backend if c["url"].endswith("/identity-matches")]


def test_the_issued_key_opens_the_inbox(client, csrf, person, carrier_backend, flow):
    inbox_key = register(client, csrf, person).get_json()["inbox_key"]

    flow.to_phone()
    assert flow.request_otp(person["name"], person["phone_number"]).status_code == 200

    body = read_inbox(client, flow.csrf_token, inbox_key).get_json()
    assert re.fullmatch(r"\d{6}", body["code"])
    assert body["issue_no"] == 1
    assert body["phone_mask"] == person["phone_number"][:3] + "-****-" + person["phone_number"][-4:]


def test_registering_again_cuts_off_the_previous_device(client, csrf, person, carrier_backend):
    """기기 하나만 유효하다. 다시 등록하면 이전 키는 못 쓴다."""
    first = register(client, csrf, person).get_json()["inbox_key"]
    second = register(client, csrf, person).get_json()["inbox_key"]
    assert first != second

    assert read_inbox(client, csrf, first).status_code == 404
    # 새 키는 수신함을 찾는다(아직 온 문자가 없으니 '인증번호 없음'이다)
    again = read_inbox(client, csrf, second)
    assert again.status_code == 404
    assert "인증번호가 없다" in again.get_json()["error"]


def test_the_key_from_people_json_still_works(client, person, carrier_backend, flow):
    """기존 경로를 끊지 않는다. seed가 넣은 키도 그대로 열린다."""
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    body = read_inbox(client, flow.csrf_token, person["inbox_key"]).get_json()
    assert re.fullmatch(r"\d{6}", body["code"])


# ---------------------------------------------------------------- 명의 확인


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "다른사람"),
        ("birth_date", "1970-01-01"),
    ],
)
def test_registration_needs_the_real_owner(client, csrf, person, carrier_backend, field, value):
    response = register(client, csrf, person, **{field: value})
    assert response.status_code == 403
    # W-14와 같은 기준: 어느 항목이 틀렸는지 알려주지 않는다
    assert response.get_json()["error"] == "등록할 수 없다. 번호와 명의를 확인한다."


def test_unknown_phone_is_refused_without_calling_the_carrier(
    client, csrf, person, carrier_backend
):
    response = register(client, csrf, person, phone_number="01000000000")
    assert response.status_code == 400
    assert not carrier_backend


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("phone_number", "0101234"),
        ("phone_number", "01912345678"),
        ("name", ""),
        ("birth_date", "19900101"),
        ("birth_date", "1990-13-01"),
        ("birth_date", ""),
    ],
)
def test_registration_rejects_bad_input(client, csrf, person, carrier_backend, field, value):
    assert register(client, csrf, person, **{field: value}).status_code == 400


def test_registration_requires_csrf(client, person, carrier_backend):
    response = client.post(
        DEVICES,
        data={
            "phone_number": person["phone_number"],
            "name": person["name"],
            "birth_date": person["birth_date"],
        },
        headers=JSON,
    )
    assert response.status_code == 400


def test_registration_is_limited_to_allowed_ips(app, client, csrf, person, carrier_backend):
    """D3: 수신함과 마찬가지로 허용 IP 밖에서는 열리지 않는다."""
    app.config["TEST_INBOX_ALLOWED_IPS"] = ["10.9.9.9"]
    assert register(client, csrf, person).status_code == 403


def test_carrier_down_is_503(client, csrf, person, monkeypatch):
    def _boom(*args, **kwargs):
        raise CarrierError("연결 실패")

    monkeypatch.setattr("app.common.carrier.register_device", _boom)
    response = register(client, csrf, person)
    assert response.status_code == 503
    assert "통신사" in response.get_json()["error"]


# ---------------------------------------------------------------- 수신함 응답


def test_inbox_returns_html_to_a_browser(client, person, carrier_backend, flow):
    """브라우저는 지금처럼 화면을 받는다."""
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    response = client.post(
        LATEST, data={"csrf_token": flow.csrf_token, "inbox_key": person["inbox_key"]}
    )
    assert response.status_code == 200
    assert "text/html" in response.headers["Content-Type"]
    assert re.search(r'class="display-6 mb-1">\d{6}<', response.get_data(as_text=True))


def test_inbox_errors_are_json_for_the_app(client, csrf):
    response = client.post(LATEST, data={"csrf_token": csrf, "inbox_key": "없는키"}, headers=JSON)
    assert response.status_code == 404
    assert response.get_json()["error"] == "수신함을 찾을 수 없다."


def test_inbox_never_returns_the_phone_number(client, person, carrier_backend, flow):
    flow.to_phone()
    flow.request_otp(person["name"], person["phone_number"])
    response = read_inbox(client, flow.csrf_token, person["inbox_key"])
    assert response.status_code == 200
    assert person["phone_number"] not in str(response.get_json())
