"""관리자 콘솔: 로그인·목록·상세·이미지 열람·접속기록·권한."""

import re
from datetime import timedelta

import pytest

from app.common.timeutil import now_utc
from app.models import AccessLog, Admin, IdDocument, Verification, db


@pytest.fixture
def person(seeded):
    return seeded[0]


def csrf_of(response) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True)).group(1)


def login_attempt(http, login_id: str, password: str) -> object:
    token = csrf_of(http.get("/admin/login"))
    return http.post(
        "/admin/login", data={"login_id": login_id, "password": password, "csrf_token": token}
    )


def test_console_requires_login(client):
    for path in ["/admin/", "/admin/access-logs", "/admin/admins"]:
        response = client.get(path)
        assert response.status_code == 302 and "/admin/login" in response.headers["Location"]


def test_login_needs_password_then_totp(app, make_admin):
    account = make_admin()
    http = app.test_client()

    assert login_attempt(http, "admin1", "verylongpassword1").status_code == 302
    # 아직 TOTP를 넣지 않았으므로 콘솔은 열리지 않는다
    assert http.get("/admin/").status_code == 302
    otp_page = http.get("/admin/otp")
    assert otp_page.status_code == 200 and "admin1" in otp_page.get_data(as_text=True)

    done = http.post(
        "/admin/otp", data={"code": account["totp"].now(), "csrf_token": csrf_of(otp_page)}
    )
    assert done.status_code == 302
    assert http.get("/admin/").status_code == 200

    db.session.expire_all()
    row = db.session.scalars(db.select(Admin).filter_by(login_id="admin1")).one()
    assert row.last_login_at is not None and row.failed_count == 0


def test_wrong_password_counts_up_and_locks(app, make_admin):
    make_admin()
    http = app.test_client()

    for expected in range(1, 5):
        assert login_attempt(http, "admin1", "wrong-password").status_code == 401
        db.session.expire_all()
        assert db.session.scalars(db.select(Admin)).one().failed_count == expected

    locked = login_attempt(http, "admin1", "wrong-password")
    assert locked.status_code == 401 and "잠겼다" in locked.get_data(as_text=True)

    db.session.expire_all()
    row = db.session.scalars(db.select(Admin)).one()
    assert row.locked_until is not None and row.locked_until > now_utc()
    assert timedelta(minutes=29) < (row.locked_until - now_utc()) <= timedelta(minutes=30)

    # 잠긴 동안은 올바른 비밀번호도 통하지 않는다
    assert login_attempt(http, "admin1", "verylongpassword1").status_code == 401


def test_wrong_totp_counts_up(app, make_admin):
    make_admin()
    http = app.test_client()
    page = http.get("/admin/login")
    token = csrf_of(page)
    http.post(
        "/admin/login",
        data={"login_id": "admin1", "password": "verylongpassword1", "csrf_token": token},
    )
    response = http.post("/admin/otp", data={"code": "000000", "csrf_token": token})
    assert response.status_code == 401
    db.session.expire_all()
    assert db.session.scalars(db.select(Admin)).one().failed_count == 1
    assert http.get("/admin/").status_code == 302


def test_unknown_account_does_not_reveal_itself(app, make_admin):
    make_admin()
    http = app.test_client()
    response = login_attempt(http, "nobody", "verylongpassword1")
    assert response.status_code == 401
    assert "올바르지 않다" in response.get_data(as_text=True)


def test_admin_ip_allowlist(app, admin_session):
    account = admin_session(allowed_ips=("10.0.0.1",))
    # 로그인 자체는 됐지만 허용 IP가 아니면 요청이 막히고 로그인 상태가 끊긴다
    assert account["http"].get("/admin/").status_code == 403
    assert account["http"].get("/admin/").status_code == 302


def test_session_timeout_is_thirty_minutes(app):
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 30 * 60


def test_list_shows_masked_values_only(admin_session, flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    flow.submit_id_info(person["rrn"], person["issue_date"])

    account = admin_session()
    response = account["http"].get("/admin/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)

    assert person["name"] not in body
    assert person["rrn"] not in body
    assert person["phone_number"] not in body
    assert mask_of(person["name"]) in body
    assert f"{person['rrn'][:6]}-{person['rrn'][6]}******" in body

    phone = db.session.get(Verification, flow.verification_id).phone
    assert phone.ci not in body  # CI는 표시하지 않는다


def mask_of(name: str) -> str:
    from app.common.log_mask import mask_name

    return mask_name(name)


def test_list_view_is_logged(admin_session):
    account = admin_session()
    account["http"].get("/admin/")
    rows = db.session.scalars(db.select(AccessLog).filter_by(action="HISTORY_VIEW")).all()
    assert rows and rows[-1].actor == "admin" and rows[-1].actor_id == "admin1"
    assert rows[-1].ip == "127.0.0.1"


def test_detail_shows_codes_and_hides_ci(admin_session, flow, carrier_backend, person, seeded):
    other = seeded[1]
    flow.to_id_card(person)
    flow.upload_id_card()
    flow.submit_id_info(other["rrn"], other["issue_date"])  # X01

    account = admin_session()
    response = account["http"].get(f"/admin/verifications/{flow.verification_id}")
    assert response.status_code == 200
    body = response.get_data(as_text=True)

    assert "X01" in body and "휴대폰 명의자와 신분증 명의자가 다르다" in body
    assert "불일치" in body
    assert other["rrn"] not in body and person["rrn"] not in body
    assert "보관 중(비표시)" in body or "파기됨" in body
    # 종결된 건이라 이미지는 파기됐다
    assert db.session.get(IdDocument, flow.verification_id).s3_key is None


def test_detail_shows_last_error_code(admin_session, flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card("noface.png")  # E01
    account = admin_session()
    body = account["http"].get(f"/admin/verifications/{flow.verification_id}").get_data(as_text=True)
    assert "E01" in body


def test_unknown_case_detail_is_404(admin_session):
    import uuid

    account = admin_session()
    assert account["http"].get(f"/admin/verifications/{uuid.uuid4()}").status_code == 404


def test_json_api_masks_by_default(admin_session, flow, carrier_backend, person, app):
    flow.to_id_card(person)
    flow.upload_id_card()
    flow.submit_id_info(person["rrn"], person["issue_date"])

    account = admin_session()
    response = account["http"].get("/admin/api/verifications")
    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 1
    item = body["items"][0]
    assert item["rrn_mask"].endswith("******")
    assert "rrn" not in item  # VULN_W10 기본 False
    assert person["rrn"] not in response.get_data(as_text=True)


def test_image_view_requires_a_reason(admin_session, flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    account = admin_session()

    short = account["http"].post(
        f"/admin/verifications/{flow.verification_id}/image",
        data={"kind": "id_card", "reason": "확인", "csrf_token": account["csrf"]},
    )
    assert short.status_code == 302 and "error=reason" in short.headers["Location"]
    assert db.session.scalars(db.select(AccessLog).filter_by(action="IMAGE_VIEW")).all() == []


def test_image_view_is_logged_with_the_reason(admin_session, flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    account = admin_session()

    response = account["http"].post(
        f"/admin/verifications/{flow.verification_id}/image",
        data={"kind": "id_card", "reason": "고객 민원 확인 건", "csrf_token": account["csrf"]},
    )
    assert response.status_code == 200

    log = db.session.scalars(db.select(AccessLog).filter_by(action="IMAGE_VIEW")).one()
    assert log.actor == "admin" and log.actor_id == "admin1"
    assert log.reason == "고객 민원 확인 건"
    assert log.target_id == f"{flow.verification_id}:id_card"

    raw = account["http"].get(f"/admin/verifications/{flow.verification_id}/image/id_card/raw")
    assert raw.status_code == 200
    assert raw.mimetype == "image/png"
    assert raw.data.startswith(b"\x89PNG")
    assert raw.headers["Cache-Control"] == "no-store"


def test_image_cannot_be_read_without_an_approval(admin_session, flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    account = admin_session()
    assert account["http"].get(
        f"/admin/verifications/{flow.verification_id}/image/id_card/raw"
    ).status_code == 403


def test_image_approval_expires(admin_session, flow, carrier_backend, person, monkeypatch):
    flow.to_id_card(person)
    flow.upload_id_card()
    account = admin_session()
    account["http"].post(
        f"/admin/verifications/{flow.verification_id}/image",
        data={"kind": "id_card", "reason": "열람 사유 테스트", "csrf_token": account["csrf"]},
    )

    import app.admin.routes as admin_routes

    monkeypatch.setattr(admin_routes, "now_utc", lambda: now_utc() + timedelta(minutes=5))
    assert account["http"].get(
        f"/admin/verifications/{flow.verification_id}/image/id_card/raw"
    ).status_code == 410


def test_purged_image_shows_as_purged(admin_session, flow, carrier_backend, sent_webhooks, person):
    flow.to_face(person)
    flow.upload_face()  # 성공 → 이미지 파기
    account = admin_session()
    response = account["http"].post(
        f"/admin/verifications/{flow.verification_id}/image",
        data={"kind": "id_card", "reason": "파기 여부 확인", "csrf_token": account["csrf"]},
    )
    assert response.status_code == 200 and "파기됨" in response.get_data(as_text=True)
    # 파기된 이미지는 열람 기록도 남기지 않는다(열람할 것이 없다)
    assert db.session.scalars(db.select(AccessLog).filter_by(action="IMAGE_VIEW")).all() == []


def test_auditor_can_read_but_not_view_images_or_change_roles(
    admin_session, flow, carrier_backend, person
):
    flow.to_id_card(person)
    flow.upload_id_card()
    account = admin_session(login_id="auditor1", role="auditor")

    assert account["http"].get("/admin/").status_code == 200
    assert account["http"].get("/admin/access-logs").status_code == 200
    assert account["http"].get(f"/admin/verifications/{flow.verification_id}").status_code == 200

    assert account["http"].get("/admin/admins").status_code == 403
    assert account["http"].post(
        f"/admin/verifications/{flow.verification_id}/image",
        data={"kind": "id_card", "reason": "권한 없는 열람 시도", "csrf_token": account["csrf"]},
    ).status_code == 403
    assert account["http"].get(
        f"/admin/verifications/{flow.verification_id}/image/id_card/raw"
    ).status_code == 403
    assert db.session.scalars(db.select(AccessLog).filter_by(action="IMAGE_VIEW")).all() == []


def test_auditor_detail_hides_the_image_form(admin_session, flow, carrier_backend, person):
    flow.to_id_card(person)
    flow.upload_id_card()
    account = admin_session(login_id="auditor1", role="auditor")
    body = account["http"].get(f"/admin/verifications/{flow.verification_id}").get_data(as_text=True)
    assert "auditor 역할은 이미지를 열람할 수 없다" in body


def test_role_change_is_logged(admin_session, make_admin):
    account = admin_session()
    target = make_admin(login_id="auditor1", role="auditor")

    response = account["http"].post(
        f"/admin/admins/{target['admin'].id}/role",
        data={"role": "admin", "csrf_token": account["csrf"]},
    )
    assert response.status_code == 302

    db.session.expire_all()
    assert db.session.get(Admin, target["admin"].id).role == "admin"
    log = db.session.scalars(db.select(AccessLog).filter_by(action="ROLE_CHANGE")).one()
    assert log.actor_id == "admin1" and log.target_id == "auditor1"
    assert log.reason == "auditor → admin"


def test_cannot_downgrade_yourself(admin_session):
    account = admin_session()
    response = account["http"].post(
        f"/admin/admins/{account['admin'].id}/role",
        data={"role": "auditor", "csrf_token": account["csrf"]},
    )
    assert response.status_code == 400
    db.session.expire_all()
    assert db.session.get(Admin, account["admin"].id).role == "admin"


def test_access_log_screen_shows_kst(admin_session):
    account = admin_session()
    account["http"].get("/admin/")
    body = account["http"].get("/admin/access-logs").get_data(as_text=True)
    assert "+09:00" in body
    assert "HISTORY_VIEW" in body


def test_logout_clears_the_session(admin_session):
    account = admin_session()
    assert account["http"].post("/admin/logout", data={"csrf_token": account["csrf"]}).status_code == 302
    assert account["http"].get("/admin/").status_code == 302
