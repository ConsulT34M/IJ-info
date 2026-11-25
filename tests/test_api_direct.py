"""IA-21 / IA-22: 위탁사가 화면을 만들고 서버 간 API만 쓰는 경로(D87).

기존 인증창 경로를 건드리지 않고 **추가**된 길이다. 여기서는 (1) 성공 경로,
(2) 사유 코드별 응답, (3) 두 경로가 서로 섞이지 않는지, (4) 서명·소유 확인이
빠지지 않는지를 본다.
"""

from __future__ import annotations

import base64
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
def direct(api_post, app):
    """DIRECT 건을 하나 만들고 제출 도우미를 돌려준다."""

    class Direct:
        def __init__(self):
            response = api_post(CREATE, {"client_user_ref": "direct-1", "mode": "DIRECT"})
            assert response.status_code == 201, response.get_json()
            self.body = response.get_json()
            self.id = self.body["verification_id"]

        def id_card(self, person, ci, **overrides):
            payload = {
                "name": person["name"],
                "rrn": person["rrn"],
                "issue_date": person["issue_date"],
                "ci": ci,
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


def test_direct_starts_at_the_id_card_stage(direct):
    assert direct.row().stage == "ID_CARD"
    assert direct.row().token_hash is None  # 인증창 토큰을 만들지 않는다


def test_the_two_modes_do_not_share_a_case(api_post):
    """같은 client_user_ref라도 방식이 다르면 다른 건이다."""
    first = api_post(CREATE, {"client_user_ref": "same", "mode": "DIRECT"}).get_json()
    second = api_post(
        CREATE, {"client_user_ref": "same", "return_url": "http://127.0.0.1:9000/done"}
    ).get_json()
    assert first["verification_id"] != second["verification_id"]


# ---------------------------------------------------------------- 성공 경로


def test_success_path(direct, person, ci_of, sent_webhooks):
    first = direct.id_card(person, ci_of(person))
    assert first.status_code == 200, first.get_json()
    assert first.get_json()["passed"] is True
    assert first.get_json()["stage"] == "FACE"

    final = direct.face()
    assert final.status_code == 200
    body = final.get_json()
    assert body["status"] == "SUCCEEDED" and body["reason_code"] == "OK"
    assert body["mode"] == "DIRECT"
    assert body["name"] == person["name"]
    # 휴대폰 단계는 A사가 하지 않았다. 위탁사가 이미 CI를 갖고 있으므로 돌려주지 않는다.
    assert body["stages"]["phone"] == "NOT_STARTED"
    assert "ci_mock" not in body
    assert len(sent_webhooks) == 1 and sent_webhooks[0]["payload"]["status"] == "SUCCEEDED"


def test_images_are_destroyed_after_the_judgement(direct, person, ci_of, sent_webhooks):
    direct.id_card(person, ci_of(person))
    direct.face()
    db.session.expire_all()
    import uuid as _uuid

    document = db.session.get(IdDocument, _uuid.UUID(direct.id))
    assert document.s3_key is None and document.deleted_at is not None
    for check in db.session.scalars(db.select(FaceCheck)).all():
        assert check.s3_key is None and check.deleted_at is not None


def test_result_is_readable_through_ia12(direct, person, ci_of, sent_webhooks, client, sign_headers):
    direct.id_card(person, ci_of(person))
    direct.face()
    response = client.get(f"{CREATE}/{direct.id}", headers=sign_headers(b""))
    assert response.status_code == 200
    assert response.get_json()["status"] == "SUCCEEDED"


def test_consents_from_the_client_are_recorded(direct, person, ci_of):
    direct.id_card(
        person,
        ci_of(person),
        consents=[
            {"type": "collect", "version": "v1.0", "agreed_at": "2026-11-25T10:00:00"},
            {"type": "uid", "version": "v1.0"},
            {"type": "bogus", "version": "v1.0"},
        ],
    )
    kinds = {row.type for row in db.session.scalars(db.select(Consent)).all()}
    assert kinds == {"collect", "uid"}  # 모르는 종류는 버린다


# ---------------------------------------------------------------- 사유 코드


def test_x01_terminates_at_once(direct, seeded, ci_of, sent_webhooks):
    """다른 사람의 CI를 보내면 재시도 없이 종결한다."""
    response = direct.id_card(seeded[0], ci_of(seeded[1]))
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "FAILED" and body["reason_code"] == "X01"
    assert direct.row().status == "FAILED"
    assert len(sent_webhooks) == 1


def test_e02_is_retryable(direct, person, ci_of):
    response = direct.id_card(person, ci_of(person), rrn="9001011234567")
    assert response.status_code == 400
    body = response.get_json()
    assert body["reason_code"] == "E02" and body["passed"] is False
    assert body["attempts_left"] == 2
    assert direct.row().status == "PENDING"


def test_e03_when_the_registry_says_lost(direct, seeded, ci_of):
    lost = seeded[8]  # 9번 인물은 진위확인 대장에서 분실이다
    response = direct.id_card(lost, ci_of(lost))
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E03"


def test_e01_on_a_bad_image(direct, person, ci_of):
    response = direct.id_card(person, ci_of(person), image=b64(b"not an image at all"))
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E01"


def test_e01_on_a_wrong_extension(direct, person, ci_of):
    response = direct.id_card(person, ci_of(person), filename="id_card.gif")
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E01"


def test_e01_on_broken_base64(direct, person, ci_of):
    response = direct.id_card(person, ci_of(person), image="!!!not base64!!!")
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E01"


def test_e04_when_no_face_is_found(direct, person, ci_of):
    direct.id_card(person, ci_of(person))
    response = direct.face(filename="noface.png")
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E04"


def test_e05_when_the_faces_differ(direct, person, ci_of):
    direct.id_card(person, ci_of(person))
    response = direct.face(filename="selfie_mismatch.png")
    assert response.status_code == 400
    assert response.get_json()["reason_code"] == "E05"


def test_e06_after_three_attempts(direct, person, ci_of, sent_webhooks):
    """D10: 얼굴 단계 실패는 합산 3회까지다."""
    direct.id_card(person, ci_of(person))
    assert direct.face(filename="selfie_mismatch.png").status_code == 400
    assert direct.face(filename="noface.png").status_code == 400
    final = direct.face(filename="selfie_mismatch.png")
    assert final.status_code == 200
    assert final.get_json()["reason_code"] == "E06"
    assert direct.row().status == "FAILED"
    assert len(sent_webhooks) == 1


def test_a_finished_case_is_409(direct, person, ci_of, sent_webhooks):
    direct.id_card(person, ci_of(person))
    direct.face()
    assert direct.face().status_code == 409


def test_an_expired_case_is_410(direct, person, ci_of, sent_webhooks):
    row = direct.row()
    # CHECK(expires_at > created_at)가 있으니 둘 다 과거로 민다
    row.created_at = now_utc() - timedelta(minutes=30)
    row.expires_at = now_utc() - timedelta(seconds=1)
    db.session.commit()
    assert direct.id_card(person, ci_of(person)).status_code == 410
    assert direct.row().reason_code == "P03"


# ---------------------------------------------------------------- 단계·경로 분리


def test_face_before_the_id_card_is_403(direct):
    assert direct.face().status_code == 403


def test_id_card_cannot_be_resubmitted_after_passing(direct, person, ci_of):
    direct.id_card(person, ci_of(person))
    assert direct.id_card(person, ci_of(person)).status_code == 403


def test_a_redirect_case_rejects_the_direct_api(api_post, person, ci_of):
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
            "ci": ci_of(person),
            "filename": "id_card.png",
            "image": b64(sample_png()),
        },
    )
    assert response.status_code == 403


def test_jpg_is_accepted(direct, person, ci_of):
    response = direct.id_card(
        person, ci_of(person), filename="id_card.jpg", image=b64(sample_jpg())
    )
    assert response.status_code == 200


# ---------------------------------------------------------------- 인증·소유


def test_signature_is_required(client, direct, person, ci_of):
    response = client.post(f"{CREATE}/{direct.id}/id-card", json={"name": person["name"]})
    assert response.status_code == 401


def test_ci_is_required(direct, person):
    response = direct.id_card(person, "")
    assert response.status_code == 400
    assert "ci" in response.get_json()["message"]


def test_a_short_ci_is_rejected(direct, person):
    assert direct.id_card(person, "x" * 87).status_code == 400


def test_another_clients_case_is_404_even_with_w08(direct, person, ci_of, enable_vuln, app):
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
    assert direct.id_card(person, ci_of(person)).status_code == 200

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
    assert direct.id_card(person, ci_of(person)).status_code == 404


def test_w09_still_requires_the_ci_match_on_the_direct_path(direct, seeded, ci_of, enable_vuln):
    """D2: 플래그를 켜도 X-01 통과는 항상 요구한다. 두 경로가 같은 함수를 쓴다."""
    lost = seeded[8]
    assert direct.id_card(lost, ci_of(lost)).status_code == 400  # E03, ci_matched=True
    enable_vuln("VULN_W09")
    # 진위확인은 건너뛰지만 CI 대조는 통과한 상태라 얼굴 단계로 들어간다
    assert direct.face(filename="selfie_mismatch.png").status_code == 400
