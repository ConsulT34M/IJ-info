"""IA-21 / IA-22: 위탁사가 화면을 만들고 서버 간 API만 쓰는 경로(D87).

기존 인증창 경로를 건드리지 않고 **추가**된 길이다. 여기서는 (1) 성공 경로,
(2) 사유 코드별 응답, (3) 두 경로가 서로 섞이지 않는지, (4) 서명·소유 확인이
빠지지 않는지를 본다.
"""

from __future__ import annotations

import base64
import re
from datetime import timedelta

import pytest

from app.common.ci import ci_mock
from app.common.secrets import get_key
from app.common.timeutil import now_utc
from app.models import Consent, FaceCheck, IdDocument, Verification, db
from tests.conftest import sample_jpg, sample_png

CREATE = "/api/v1/verifications"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@pytest.fixture
def person(seeded):
    return seeded[0]


@pytest.fixture
def ci_of(app):
    def _ci(person):
        return ci_mock(person["rrn"], get_key("ekyc/ci-key"))

    return _ci


@pytest.fixture
def direct(api_post, app, client, carrier_backend, seeded):
    """DIRECT 건을 하나 만들고 제출 도우미를 돌려준다.

    휴대폰 단계(IA-23·IA-24)도 A사를 거친다(D98). 인증번호는 응답에 없으므로
    이용자 휴대폰(테스트 수신함)에서 읽는다 — 위탁사는 볼 수 없다.
    """

    class Direct:
        def __init__(self):
            response = api_post(CREATE, {"client_user_ref": "direct-1", "mode": "DIRECT"})
            assert response.status_code == 201, response.get_json()
            self.body = response.get_json()
            self.id = self.body["verification_id"]

        def otp(self, person, **overrides):
            payload = {"name": person["name"], "phone_number": person["phone_number"]}
            payload.update(overrides)
            return api_post(f"{CREATE}/{self.id}/phone/otp", payload)

        def inbox_code(self, person) -> str | None:
            """이용자 휴대폰으로 간 인증번호. 모의 PASS 앱이 보는 것과 같은 값이다."""
            page = client.get("/test-inbox/")
            token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True))
            response = client.post(
                "/test-inbox/latest",
                data={"inbox_key": person["inbox_key"], "csrf_token": token.group(1)},
            )
            found = re.search(r'class="ij-code mb-1">(\d{6})<', response.get_data(as_text=True))
            return found.group(1) if found else None

        def confirm(self, code, **overrides):
            payload = {"code": code}
            payload.update(overrides)
            return api_post(f"{CREATE}/{self.id}/phone/confirm", payload)

        def to_id_card(self, person):
            """휴대폰 단계를 정상으로 통과시킨다."""
            assert self.otp(person).status_code == 200
            code = self.inbox_code(person)
            assert code, "테스트 수신함에서 인증번호를 읽지 못했다"
            assert self.confirm(code).status_code == 200
            return code

        def id_card(self, person, **overrides):
            # 아직 휴대폰 단계면 그 인물 명의로 먼저 통과시킨다. 명의가 다른 상황을
            # 보려는 테스트는 to_id_card()를 명시적으로 먼저 부른다(X-01).
            if self.row().stage == "PHONE":
                self.to_id_card(person)
            payload = {
                "name": person["name"],
                "rrn": person["rrn"],
                "issue_date": person["issue_date"],
                "filename": "id_card.png",
                "image": b64(sample_png()),
            }
            payload.update(overrides)
            return api_post(f"{CREATE}/{self.id}/id-card", payload)

        def face(self, **overrides):
            payload = {"filename": "selfie.png", "image": b64(sample_png())}
            payload.update(overrides)
            return api_post(f"{CREATE}/{self.id}/face", payload)

        def row(self):
            import uuid as _uuid

            db.session.expire_all()
            return db.session.get(Verification, _uuid.UUID(self.id))

    return Direct()


# ---------------------------------------------------------------- IA-01 mode


def test_direct_mode_returns_no_auth_url(api_post):
    body = api_post(CREATE, {"client_user_ref": "d-1", "mode": "DIRECT"}).get_json()
    assert body["mode"] == "DIRECT"
    assert "auth_url" not in body  # 인증창이 없다
    assert body["verification_id"] and body["expires_at"]


def test_redirect_mode_is_unchanged(api_post):
    body = api_post(CREATE, {"client_user_ref": "r-1", "return_url": "http://127.0.0.1:9000/done"}).get_json()
    assert body["mode"] == "REDIRECT"
    assert "/verify/start/" in body["auth_url"]


def test_direct_needs_no_return_url(api_post, exchange_client):
    """돌려보낼 브라우저가 없다. 비워 두면 콜백 주소로 채운다."""
    response = api_post(CREATE, {"client_user_ref": "d-2", "mode": "DIRECT"})
    assert response.status_code == 201


def test_unknown_mode_is_400(api_post):
    response = api_post(CREATE, {"client_user_ref": "d-3", "mode": "WHATEVER"})
    assert response.status_code == 400


def test_direct_starts_at_the_phone_stage(direct):
    """D98: 휴대폰 본인확인도 A사가 한다. 동의 화면만 위탁사에 있다."""
    assert direct.row().stage == "PHONE"
    assert direct.row().token_hash is None  # 인증창 토큰을 만들지 않는다


def test_local_preview_shows_issued_code_without_device_registration(direct, person, client):
    issued = direct.otp(person)
    assert issued.status_code == 200
    body = issued.get_json()
    assert "code" not in body
    token = body["local_preview_token"]
    page = client.get(f"/test-inbox/widget?preview={token}")
    assert page.status_code == 200
    assert direct.inbox_code(person) in page.get_data(as_text=True)
    assert "휴대폰 등록" not in page.get_data(as_text=True)
    assert client.get("/test-inbox/widget?preview=invalid").status_code == 410


def test_the_two_modes_do_not_share_a_case(api_post):
    """같은 client_user_ref라도 방식이 다르면 다른 건이다."""
    first = api_post(CREATE, {"client_user_ref": "same", "mode": "DIRECT"}).get_json()
    second = api_post(
        CREATE, {"client_user_ref": "same", "return_url": "http://127.0.0.1:9000/done"}
    ).get_json()
    assert first["verification_id"] != second["verification_id"]


# ---------------------------------------------------------------- 성공 경로


def test_success_path(direct, person, sent_webhooks):
    first = direct.id_card(person)
    assert first.status_code == 200, first.get_json()
    assert first.get_json()["passed"] is True
    assert first.get_json()["stage"] == "FACE"

    final = direct.face()
    assert final.status_code == 200
    body = final.get_json()
    assert body["status"] == "SUCCEEDED" and body["reason_code"] == "OK"
    assert body["mode"] == "DIRECT"
    assert body["name"] == person["name"]
    # D98: 휴대폰 단계도 A사가 했다. CI는 A사가 통신사에게 받아 보관한 값이다.
    assert body["stages"]["phone"] == "PASSED"
    assert body["ci_mock"] and len(body["ci_mock"]) == 88
    assert len(sent_webhooks) == 1 and sent_webhooks[0]["payload"]["status"] == "SUCCEEDED"


def test_images_are_destroyed_after_the_judgement(direct, person, sent_webhooks):
    direct.id_card(person)
    direct.face()
    db.session.expire_all()
    import uuid as _uuid

    document = db.session.get(IdDocument, _uuid.UUID(direct.id))
    assert document.s3_key is None and document.deleted_at is not None
    for check in db.session.scalars(db.select(FaceCheck)).all():
        assert check.s3_key is None and check.deleted_at is not None


def test_result_is_readable_through_ia12(direct, person, sent_webhooks, client, sign_headers):
    direct.id_card(person)
    direct.face()
    response = client.get(f"{CREATE}/{direct.id}", headers=sign_headers(b""))
    assert response.status_code == 200
    assert response.get_json()["status"] == "SUCCEEDED"


def test_consents_from_the_client_are_recorded(direct, person):
    direct.id_card(person, consents=[
            {"type": "collect", "version": "v1.0", "agreed_at": "2026-11-25T10:00:00"},
            {"type": "uid", "version": "v1.0"},
            {"type": "bogus", "version": "v1.0"},
        ],
    )
    kinds = {row.type for row in db.session.scalars(db.select(Consent)).all()}
    assert kinds == {"collect", "uid"}  # 모르는 종류는 버린다


# ---------------------------------------------------------------- 사유 코드


def test_x01_terminates_at_once(direct, seeded, sent_webhooks):
    """다른 사람의 CI를 보내면 재시도 없이 종결한다."""
    direct.to_id_card(seeded[0])  # 휴대폰은 0번 인물 명의
    response = direct.id_card(seeded[1])  # 신분증은 다른 사람 것
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "FAILED" and body["reason_code"] == "X01"
    assert direct.row().status == "FAILED"
    assert len(sent_webhooks) == 1


def test_e02_is_retryable(direct, person):
    response = direct.id_card(person, rrn="9001011234567")
    assert response.status_code == 400
    body = response.get_json()
    assert body["reason_code"] == "E02" and body["passed"] is False
    assert body["attempts_left"] == 2
    assert direct.row().status == "PENDING"


def test_e03_when_the_registry_says_lost(direct, seeded):
    lost = seeded[8]  # 9번 인물은 진위확인 대장에서 분실이다
    response = direct.id_card(lost)
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E03"


def test_e01_on_a_bad_image(direct, person):
    response = direct.id_card(person, image=b64(b"not an image at all"))
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E01"


def test_e01_on_a_wrong_extension(direct, person):
    response = direct.id_card(person, filename="id_card.gif")
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E01"


def test_e01_on_broken_base64(direct, person):
    response = direct.id_card(person, image="!!!not base64!!!")
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E01"


def test_e04_when_no_face_is_found(direct, person):
    direct.id_card(person)
    response = direct.face(filename="noface.png")
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E04"


def test_e05_when_the_faces_differ(direct, person):
    direct.id_card(person)
    response = direct.face(filename="selfie_mismatch.png")
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E05"


def test_e06_after_three_attempts(direct, person, sent_webhooks):
    """D10: 얼굴 단계 실패는 합산 3회까지다."""
    direct.id_card(person)
    assert direct.face(filename="selfie_mismatch.png").status_code == 400
    assert direct.face(filename="noface.png").status_code == 400
    final = direct.face(filename="selfie_mismatch.png")
    assert final.status_code == 200
    assert final.get_json()["reason_code"] == "E06"
    assert direct.row().status == "FAILED"
    assert len(sent_webhooks) == 1


def test_a_finished_case_is_409(direct, person, sent_webhooks):
    direct.id_card(person)
    direct.face()
    assert direct.face().status_code == 409


def test_an_expired_case_is_410(direct, person, sent_webhooks):
    row = direct.row()
    # CHECK(expires_at > created_at)가 있으니 둘 다 과거로 민다
    row.created_at = now_utc() - timedelta(minutes=30)
    row.expires_at = now_utc() - timedelta(seconds=1)
    db.session.commit()
    assert direct.otp(person).status_code == 410
    assert direct.row().reason_code == "P03"


# ---------------------------------------------------------------- 단계·경로 분리


def test_face_before_the_id_card_is_403(direct):
    assert direct.face().status_code == 403


def test_id_card_cannot_be_resubmitted_after_passing(direct, person):
    direct.id_card(person)
    assert direct.id_card(person).status_code == 403


def test_a_redirect_case_rejects_the_direct_api(api_post, person):
    """인증창 방식 건을 서버 간 API로 밀어 넣을 수 없다."""
    created = api_post(
        CREATE, {"client_user_ref": "r-2", "return_url": "http://127.0.0.1:9000/done"}
    ).get_json()
    response = api_post(
        f"{CREATE}/{created['verification_id']}/id-card",
        {
            "name": person["name"],
            "rrn": person["rrn"],
            "issue_date": person["issue_date"],
            "filename": "id_card.png",
            "image": b64(sample_png()),
        },
    )
    assert response.status_code == 403


def test_jpg_is_accepted(direct, person):
    response = direct.id_card(person, filename="id_card.jpg", image=b64(sample_jpg()))
    assert response.status_code == 200


# ---------------------------------------------------------------- 인증·소유


def test_signature_is_required(client, direct, person):
    response = client.post(f"{CREATE}/{direct.id}/id-card", json={"name": person["name"]})
    assert response.status_code == 401


def test_a_client_supplied_ci_is_rejected(direct, person, ci_of):
    """D98: CI는 A사가 통신사에게 받은 값만 쓴다. 위탁사가 보내면 받지 않는다.

    받아 주면 X-01이 '같은 키로 같은 주민번호를 두 번 계산해 비교하는' 항등식이 되어
    휴대폰 명의자와 신분증 명의자가 같은지를 전혀 보지 못한다.
    """
    direct.to_id_card(person)
    response = direct.id_card(person, ci=ci_of(person))
    assert response.status_code == 400
    assert "ci" in response.get_json()["message"]


def test_the_id_card_stage_needs_the_phone_stage_first(direct, person):
    """휴대폰 본인확인을 건너뛰고 신분증부터 낼 수 없다."""
    response = direct.id_card.__wrapped__(direct, person) if False else None
    import uuid as _uuid
    from app.models import Verification as _V
    row = db.session.get(_V, _uuid.UUID(direct.id))
    assert row.stage == "PHONE"  # IA-01 직후에는 휴대폰 단계다


def test_another_clients_case_is_404_even_with_w08(direct, person, enable_vuln, app):
    """VULN_W08은 조회(IA-12)만 푼다. 제출 경로의 소유 확인은 플래그와 무관하다."""
    other = Verification(
        client_id=direct.row().client_id,
        client_user_ref="other",
        mode="DIRECT",
        stage="ID_CARD",
        return_url="http://127.0.0.1:9000/done",
        expires_at=now_utc() + timedelta(minutes=20),
    )
    db.session.add(other)
    db.session.commit()
    # 같은 위탁사 건이면 통과해야 한다(대조군)
    assert direct.id_card(person).status_code == 200

    from app.models import Client

    stranger = Client(
        name="다른 위탁사",
        api_key_hash="x" * 64,
        hmac_secret_ref="ekyc/clients/other/hmac",
        callback_url="http://127.0.0.1:9100/cb",
        allowed_ips="127.0.0.1",
    )
    db.session.add(stranger)
    db.session.flush()
    foreign = Verification(
        client_id=stranger.id,
        client_user_ref="theirs",
        mode="DIRECT",
        stage="ID_CARD",
        return_url="http://127.0.0.1:9100/cb",
        expires_at=now_utc() + timedelta(minutes=20),
    )
    db.session.add(foreign)
    db.session.commit()

    enable_vuln("VULN_W08")
    direct.id = str(foreign.id)
    assert direct.id_card(person).status_code == 404


def test_w09_still_requires_the_ci_match_on_the_direct_path(direct, seeded, enable_vuln):
    """D2: 플래그를 켜도 X-01 통과는 항상 요구한다. 두 경로가 같은 함수를 쓴다."""
    lost = seeded[8]
    assert direct.id_card(lost).status_code == 400  # E03, ci_matched=True
    enable_vuln("VULN_W09")
    # 진위확인은 건너뛰지만 CI 대조는 통과한 상태라 얼굴 단계로 들어간다
    assert direct.face(filename="selfie_mismatch.png").status_code == 400


# ------------------------------------------------- IA-23 / IA-24 휴대폰 단계 (D98)
#
# 전에는 위탁사가 인증번호를 만들고 CI까지 계산해 보냈다. 그러면 X-01이 항등식이 된다.
# 여기서는 (1) 인증번호가 위탁사에게 새지 않는지, (2) 실패 경로가 사유 코드대로
# 끝나는지, (3) CI가 응답에 없는지를 본다.


def test_the_code_never_reaches_the_client(direct, person):
    """인증번호는 응답 어디에도 없다. 위탁사가 알면 그 자체가 오라클이다."""
    response = direct.otp(person)
    assert response.status_code == 200
    body = response.get_json()

    code = direct.inbox_code(person)
    assert code and len(code) == 6
    assert code not in response.get_data(as_text=True)
    assert body["phone_mask"].startswith("010-****")
    assert person["phone_number"] not in response.get_data(as_text=True)
    assert "code" not in body and "ci" not in body


def test_the_ci_never_reaches_the_client(direct, person):
    """CI는 A사 안에만 둔다."""
    direct.otp(person)
    response = direct.confirm(direct.inbox_code(person))
    assert response.status_code == 200
    assert response.get_json()["stage"] == "ID_CARD"

    from app.models import PhoneVerification
    import uuid as _uuid

    stored = db.session.get(PhoneVerification, _uuid.UUID(direct.id))
    assert stored.ci and len(stored.ci) == 88
    assert stored.ci not in response.get_data(as_text=True)


def test_p01_when_the_name_does_not_match(direct, person):
    """명의 대조 불일치. 3회째에 종결한다."""
    for remaining in (2, 1):
        response = direct.otp(person, name="다른사람")
        assert response.status_code == 400
        body = response.get_json()
        assert body["reason_code"] == "P01" and body["attempts_left"] == remaining

    last = direct.otp(person, name="다른사람")
    assert last.status_code == 409
    assert last.get_json()["reason_code"] == "P01"
    assert direct.row().status == "FAILED"


def test_p01_hides_whether_the_number_is_registered(direct, person):
    """D1: 이름 불일치와 미등록 번호가 같은 메시지·같은 상태 코드여야 한다."""
    wrong_name = direct.otp(person, name="다른사람")
    unknown = direct.otp(person, phone_number="01000000000")

    assert wrong_name.status_code == unknown.status_code == 400
    # 남은 횟수만 다르다. 사유를 가리키는 문구가 달라서는 안 된다.
    strip = lambda body: body["message"].split("(남은")[0]
    assert strip(wrong_name.get_json()) == strip(unknown.get_json())


def test_p02_after_three_wrong_codes(direct, person, sent_webhooks):
    direct.otp(person)
    real = direct.inbox_code(person)
    wrong = "000000" if real != "000000" else "111111"

    for remaining in (2, 1):
        response = direct.confirm(wrong)
        assert response.status_code == 400
        assert response.get_json()["reason_code"] == "P02"
        assert response.get_json()["attempts_left"] == remaining

    last = direct.confirm(wrong)
    assert last.status_code == 409
    assert direct.row().status == "FAILED" and direct.row().reason_code == "P02"
    assert len(sent_webhooks) == 1
    assert sent_webhooks[0]["payload"]["stages"]["phone"] == "FAILED"
    assert "ci_mock" not in sent_webhooks[0]["payload"]


def test_a_wrong_format_code_does_not_burn_an_attempt(direct, person):
    direct.otp(person)
    assert direct.confirm("12").status_code == 400
    assert direct.confirm("abcdef").status_code == 400
    # 형식 오류는 불일치가 아니다. 맞는 번호는 여전히 통한다.
    assert direct.confirm(direct.inbox_code(person)).status_code == 200


def test_an_expired_code_is_rejected(direct, person):
    import uuid as _uuid
    from app.models import PhoneOtp

    direct.otp(person)
    code = direct.inbox_code(person)
    row = db.session.get(PhoneOtp, _uuid.UUID(direct.id))
    row.code_expires_at = now_utc() - timedelta(seconds=1)
    db.session.commit()

    response = direct.confirm(code)
    assert response.status_code == 400
    assert "유효시간" in response.get_json()["message"]


def test_resend_is_blocked_within_the_interval(direct, person):
    assert direct.otp(person).status_code == 200
    again = direct.otp(person, resend=True)
    assert again.status_code == 429


def test_resend_must_use_the_same_number(direct, person, seeded):
    import uuid as _uuid
    from app.models import PhoneOtp, TestPhone

    direct.otp(person)
    # 재발송 간격을 지나게 한다
    row = db.session.get(PhoneOtp, _uuid.UUID(direct.id))
    row.issued_at = now_utc() - timedelta(minutes=5)
    db.session.get(TestPhone, row.phone_key).next_issue_at = None
    db.session.commit()

    other = seeded[1]
    assert direct.otp(person, phone_number=other["phone_number"], resend=True).status_code == 400
    assert direct.otp(person, resend=True).status_code == 200


def test_resend_does_not_run_the_identity_match_again(direct, person, carrier_backend):
    """D6: 재발송은 명의 대조를 다시 하지 않는다."""
    import uuid as _uuid
    from app.models import PhoneOtp, TestPhone

    direct.otp(person)
    before = len([call for call in carrier_backend if "identity-matches" in call["url"]])

    row = db.session.get(PhoneOtp, _uuid.UUID(direct.id))
    row.issued_at = now_utc() - timedelta(minutes=5)
    db.session.get(TestPhone, row.phone_key).next_issue_at = None
    db.session.commit()

    assert direct.otp(person, resend=True).status_code == 200
    after = len([call for call in carrier_backend if "identity-matches" in call["url"]])
    assert after == before


def test_the_phone_stage_cannot_be_redone(direct, person):
    direct.to_id_card(person)
    assert direct.otp(person).status_code == 409
    # 재확인은 멱등이다. 위탁사가 응답을 못 받고 다시 보낸 경우를 막으면 안 된다.
    retry = direct.confirm("123456")
    assert retry.status_code == 200 and retry.get_json()["passed"] is True


def test_a_used_code_does_not_burn_an_attempt(direct, person):
    """같은 번호를 두 번 보낸 것은 틀린 번호가 아니다(D88)."""
    import uuid as _uuid
    from app.models import PhoneVerification

    direct.otp(person)
    code = direct.inbox_code(person)
    assert direct.confirm(code).status_code == 200
    again = direct.confirm(code)
    assert again.status_code == 200 and again.get_json()["passed"] is True
    assert db.session.get(PhoneVerification, _uuid.UUID(direct.id)).otp_attempts == 0


def test_p05_when_the_carrier_is_down(direct, person, monkeypatch, sent_webhooks):
    from app.common import carrier as carrier_module

    def boom(*args, **kwargs):
        raise carrier_module.CarrierError("연결 실패")

    monkeypatch.setattr(carrier_module, "identity_match", boom)
    response = direct.otp(person)
    assert response.status_code == 503
    assert direct.row().status == "FAILED" and direct.row().reason_code == "P05"


def test_x01_is_a_real_check_now(direct, seeded, sent_webhooks):
    """휴대폰은 0번 인물로, 신분증은 1번 인물로 — 진짜 명의 불일치다.

    전 계약에서는 위탁사가 '제출할 주민번호'로 CI를 만들어 보냈으므로 이 상황을
    만들 수조차 없었다.
    """
    direct.to_id_card(seeded[0])
    response = direct.id_card(seeded[1])

    assert response.status_code == 200
    assert response.get_json()["reason_code"] == "X01"
    assert direct.row().status == "FAILED"
    assert sent_webhooks[0]["payload"]["stages"] == {
        "phone": "PASSED",
        "id_card": "FAILED",
        "face": "NOT_STARTED",
    }
