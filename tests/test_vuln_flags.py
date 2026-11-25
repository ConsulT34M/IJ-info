"""취약 플래그 6개: "기본값에서는 막힌다" / "플래그를 켜면 뚫린다" 쌍.

진단 증적의 기준이다. 각 플래그마다 테스트가 두 개씩 있고, 이름이 `_is_blocked_by_default`
/ `_is_exposed_when_enabled` 로 끝난다.
기본값은 전부 False이므로 `enable_vuln` 픽스처가 켜기 전에 기본값을 한 번 더 확인한다.
"""

import logging
import uuid
from datetime import timedelta

import pytest

from app.common import secrets as secrets_mod
from app.common.ci import ci_mock
from app.common.hmac_auth import api_key_hash, generate_api_key
from app.common.storage import get_storage
from app.common.timeutil import now_utc
from app.config import VULN_FLAGS, enabled_vuln_flags
from app.models import Client, IdDocument, Verification, db

IA12 = "/api/v1/verifications"
ADMIN_JSON = "/admin/api/verifications"
UNKNOWN_PHONE = "01099998888"


@pytest.fixture
def person(seeded):
    return seeded[0]


@pytest.fixture
def other_person(seeded):
    return seeded[1]


@pytest.fixture
def lost_person(seeded):
    """9번 인물. 진위확인 대장에서 분실 → E03."""
    return [p for p in seeded if p["person_no"] == 9][0]


@pytest.fixture
def api_get(client, sign_headers):
    def _get(path: str, **kwargs):
        return client.get(path, headers=sign_headers(b"", **kwargs))

    return _get


# --- 공통 ------------------------------------------------------------------


def test_every_flag_defaults_to_false(app):
    assert set(VULN_FLAGS) == {
        # CLAUDE.md 14장
        "VULN_W08",
        "VULN_W09",
        "VULN_W10",
        "VULN_W14",
        "VULN_W17",
        "VULN_C10",
        # 홈페이지 자료실·문의에서만 쓰는 웹 점검용(D90)
        "VULN_W01",
        "VULN_W02",
        "VULN_W05",
    }
    for flag in VULN_FLAGS:
        assert app.config[flag] is False, flag
    assert enabled_vuln_flags(app) == []


def test_enabled_flags_are_listed(app, enable_vuln):
    enable_vuln("VULN_W08", "VULN_C10")
    assert enabled_vuln_flags(app) == ["VULN_W08", "VULN_C10"]


# --- VULN_W08: IA-12 소유 확인 -----------------------------------------------


@pytest.fixture
def other_clients_case(flow, carrier_backend, sent_webhooks, person):
    """성공 완주한 건을 만든 뒤 다른 위탁사 소유로 바꾼다."""
    flow.to_face(person)
    assert flow.upload_face().status_code == 302
    other = Client(
        name="다른 거래소",
        api_key_hash=api_key_hash(generate_api_key()),
        hmac_secret_ref="ekyc/clients/other/hmac",
        callback_url="http://127.0.0.1:9100/callback",
        allowed_ips=["127.0.0.1"],
    )
    db.session.add(other)
    db.session.flush()
    verification = db.session.get(Verification, flow.verification_id)
    verification.client_id = other.id
    db.session.commit()
    return flow.verification_id


def test_w08_other_clients_case_is_blocked_by_default(app, api_get, other_clients_case):
    assert app.config["VULN_W08"] is False
    response = api_get(f"{IA12}/{other_clients_case}")
    assert response.status_code == 404
    assert "verification_id" not in response.get_json()


def test_w08_other_clients_case_is_exposed_when_enabled(
    enable_vuln, api_get, other_clients_case, person
):
    enable_vuln("VULN_W08")
    response = api_get(f"{IA12}/{other_clients_case}")
    assert response.status_code == 200

    body = response.get_json()
    assert body["verification_id"] == str(other_clients_case)
    assert body["status"] == "SUCCEEDED"
    # 다른 위탁사 이용자의 성명·생년월일·CI가 그대로 나간다
    assert body["name"] == person["name"]
    assert body["birth_date"] == person["birth_date"]
    assert body["ci_mock"] == ci_mock(person["rrn"], secrets_mod.get_key("ekyc/ci-key"))


# --- VULN_W09: 얼굴 단계의 진위확인 우회 --------------------------------------


@pytest.fixture
def stuck_at_e03(flow, carrier_backend, sent_webhooks, lost_person):
    """진위확인에서 걸린 상태(stage=ID_CONFIRM, ci_matched True, mois_matched False)."""
    flow.to_id_card(lost_person)
    assert flow.upload_id_card().status_code == 302
    assert flow.submit_id_info(lost_person["rrn"], lost_person["issue_date"]).status_code == 400

    document = db.session.get(IdDocument, flow.verification_id)
    assert document.ci_matched is True and document.mois_matched is False
    assert db.session.get(Verification, flow.verification_id).stage == "ID_CONFIRM"
    return flow.verification_id


def test_w09_face_step_is_blocked_by_default(app, flow, stuck_at_e03, sent_webhooks):
    assert app.config["VULN_W09"] is False
    # stage가 FACE가 아니고 진위확인도 통과하지 않았으므로 막힌다
    assert flow.upload_face().status_code == 403

    verification = db.session.get(Verification, stuck_at_e03)
    assert verification.status == "PENDING" and verification.stage == "ID_CONFIRM"
    assert sent_webhooks == []


def test_w09_face_step_is_exposed_when_enabled(enable_vuln, flow, stuck_at_e03, sent_webhooks):
    enable_vuln("VULN_W09")
    # 진위확인을 통과하지 않은 건이 얼굴 대조만으로 최종 판정된다
    response = flow.upload_face()
    assert response.status_code == 302 and response.headers["Location"] == "/verify/result"

    verification = db.session.get(Verification, stuck_at_e03)
    assert verification.status == "SUCCEEDED" and verification.reason_code == "OK"

    payload = sent_webhooks[0]["payload"]
    assert payload["status"] == "SUCCEEDED"
    # 증적: 성공인데 신분증 단계는 FAILED다(진위확인을 통과하지 않았다)
    assert payload["stages"] == {"phone": "PASSED", "id_card": "FAILED", "face": "PASSED"}
    assert db.session.get(IdDocument, stuck_at_e03).mois_matched is False


def test_w09_still_requires_the_ci_match_when_enabled(enable_vuln, flow, stuck_at_e03, sent_webhooks):
    """D2: 플래그를 켜도 CI 대조(X-01) 통과는 항상 요구한다. W-09가 W-13까지 뚫지 않는다."""
    enable_vuln("VULN_W09")
    document = db.session.get(IdDocument, stuck_at_e03)
    document.ci_matched = None
    db.session.commit()

    assert flow.upload_face().status_code == 403
    assert db.session.get(Verification, stuck_at_e03).status == "PENDING"
    assert sent_webhooks == []


# --- VULN_W10: 관리자 목록 JSON의 주민번호 --------------------------------------


@pytest.fixture
def case_with_rrn(flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    assert flow.submit_id_info(person["rrn"], person["issue_date"]).status_code == 302
    return flow.verification_id


def test_w10_rrn_is_masked_by_default(app, admin_session, case_with_rrn, person):
    assert app.config["VULN_W10"] is False
    account = admin_session()
    response = account["http"].get(ADMIN_JSON)
    assert response.status_code == 200

    item = response.get_json()["items"][0]
    assert item["rrn_mask"] == f"{person['rrn'][:6]}-{person['rrn'][6]}******"
    assert "rrn" not in item
    assert person["rrn"] not in response.get_data(as_text=True)


def test_w10_rrn_is_exposed_when_enabled(enable_vuln, admin_session, case_with_rrn, person):
    enable_vuln("VULN_W10")
    account = admin_session()
    response = account["http"].get(ADMIN_JSON)
    assert response.status_code == 200

    item = response.get_json()["items"][0]
    # 마스킹을 화면 JS에 맡기고 API는 원문을 내보낸다
    assert item["rrn"] == person["rrn"]
    assert person["rrn"] in response.get_data(as_text=True)


def test_w10_html_list_stays_masked_either_way(enable_vuln, admin_session, case_with_rrn, person):
    """화면(HTML)은 플래그와 무관하게 마스킹된다 — 그래서 JSON을 직접 봐야 드러난다."""
    enable_vuln("VULN_W10")
    account = admin_session()
    body = account["http"].get("/admin/").get_data(as_text=True)
    assert person["rrn"] not in body


# --- VULN_W14: 명의 대조 실패 사유 노출 ----------------------------------------


def _match_failure(flow, name: str, phone_number: str):
    return flow.request_otp(name, phone_number)


def test_w14_failure_reasons_look_the_same_by_default(app, flow, carrier_backend, person):
    assert app.config["VULN_W14"] is False
    flow.to_phone()

    wrong_name = _match_failure(flow, "다른이름", person["phone_number"])
    unknown_number = _match_failure(flow, person["name"], UNKNOWN_PHONE)

    assert wrong_name.status_code == 200 and unknown_number.status_code == 200
    first = wrong_name.get_data(as_text=True)
    second = unknown_number.get_data(as_text=True)
    assert "성명 또는 휴대폰번호가 일치하지 않습니다" in first
    assert "성명 또는 휴대폰번호가 일치하지 않습니다" in second
    assert "등록되지 않은" not in second
    assert "명의자와 다릅니다" not in first


def test_w14_failure_reasons_are_exposed_when_enabled(enable_vuln, flow, carrier_backend, person):
    enable_vuln("VULN_W14")
    flow.to_phone()

    wrong_name = _match_failure(flow, "다른이름", person["phone_number"])
    assert wrong_name.status_code == 400
    assert "입력하신 성명이 명의자와 다릅니다" in wrong_name.get_data(as_text=True)

    unknown_number = _match_failure(flow, person["name"], UNKNOWN_PHONE)
    assert unknown_number.status_code == 404
    assert "등록되지 않은 휴대폰번호입니다" in unknown_number.get_data(as_text=True)

    # 응답 코드만으로 그 번호가 가입된 번호인지 알 수 있다(열거 오라클)
    assert wrong_name.status_code != unknown_number.status_code


# --- VULN_W17: 인증번호·번호 원문 로그 -----------------------------------------


def test_w17_code_is_not_logged_by_default(app, flow, carrier_backend, person, caplog):
    assert app.config["VULN_W17"] is False
    flow.to_phone()
    with caplog.at_level(logging.DEBUG):
        assert flow.request_otp(person["name"], person["phone_number"]).status_code == 200
        code = flow.inbox_code(person["inbox_key"])

    assert code is not None
    assert code not in caplog.text
    assert person["phone_number"] not in caplog.text
    assert person["name"] not in caplog.text


def test_w17_code_is_logged_when_enabled(enable_vuln, flow, carrier_backend, person, caplog):
    enable_vuln("VULN_W17")
    flow.to_phone()
    with caplog.at_level(logging.DEBUG):
        assert flow.request_otp(person["name"], person["phone_number"]).status_code == 200
        code = flow.inbox_code(person["inbox_key"])

    # 마스킹 필터를 거치지 않는 로거로 원문이 남는다
    assert code in caplog.text
    assert person["phone_number"] in caplog.text
    assert "ekyc.vuln" in [record.name for record in caplog.records]


def test_w17_masking_filter_itself_still_works(app, enable_vuln, caplog):
    """플래그는 '필터를 우회하는 다른 로거'를 쓰는 것이고, 필터 자체를 끄는 것이 아니다."""
    enable_vuln("VULN_W17")
    with caplog.at_level(logging.INFO):
        app.logger.info("phone=%s code=%s", "01012341234", "123456")
    assert "01012341234" not in caplog.text and "123456" not in caplog.text


# --- VULN_C10: 파기 배치가 Storage 객체를 남긴다 --------------------------------


@pytest.fixture
def finished_case_with_image(flow, carrier_backend, person):
    """종결됐지만 이미지가 남아 있는 건(중단된 배치·과거 데이터를 가정)."""
    flow.to_id_card(person)
    assert flow.upload_id_card().status_code == 302
    verification = db.session.get(Verification, flow.verification_id)
    verification.status = "FAILED"
    verification.reason_code = "E06"
    verification.completed_at = now_utc()
    db.session.commit()

    key = db.session.get(IdDocument, flow.verification_id).s3_key
    assert key and get_storage().exists(key)
    return {"verification_id": flow.verification_id, "key": key}


def test_c10_object_is_deleted_by_default(app, runner, finished_case_with_image):
    from app.cli import purge_command

    assert app.config["VULN_C10"] is False
    result = runner.invoke(purge_command)
    assert result.exit_code == 0, result.output
    assert "VULN_C10" not in result.output

    db.session.expire_all()
    document = db.session.get(IdDocument, finished_case_with_image["verification_id"])
    assert document.s3_key is None and document.deleted_at is not None
    # DB 참조와 객체가 함께 사라진다
    assert get_storage().exists(finished_case_with_image["key"]) is False


def test_c10_object_is_left_behind_when_enabled(enable_vuln, runner, finished_case_with_image):
    from app.cli import purge_command

    enable_vuln("VULN_C10")
    result = runner.invoke(purge_command)
    assert result.exit_code == 0, result.output
    assert "DB 참조만 지우고 Storage 객체는 남긴다" in result.output

    db.session.expire_all()
    document = db.session.get(IdDocument, finished_case_with_image["verification_id"])
    # DB는 "파기됨"이라고 말하는데
    assert document.s3_key is None and document.deleted_at is not None
    # 실제 파일은 그대로 남아 있다
    assert get_storage().exists(finished_case_with_image["key"]) is True
    assert get_storage().load(finished_case_with_image["key"]).startswith(b"\x89PNG")


def test_c10_judgement_time_purge_is_unaffected(enable_vuln, flow, carrier_backend, sent_webhooks, person):
    """C10은 파기 배치(F-14)만 바꾼다. 판정 즉시 파기는 그대로 동작한다."""
    enable_vuln("VULN_C10")
    flow.to_face(person)
    key = db.session.get(IdDocument, flow.verification_id).s3_key
    assert flow.upload_face().status_code == 302
    assert get_storage().exists(key) is False
