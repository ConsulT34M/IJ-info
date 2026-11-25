"""홈페이지 자료실·문의 저장과 웹 점검용 플래그 3개(D90).

금취분평 웹 항목 중 **SQL 인젝션 · 저장형 XSS · 다운로드 경로 조작**을 재현해 볼
대상이다. 기본값은 전부 양호이고, 플래그를 켰을 때만 뚫린다.
"""

from __future__ import annotations

import re
from datetime import date

import pytest

from app.models import SiteDocument, SiteInquiry, db

LIBRARY = "/library"
DOWNLOAD = "/library/download"


@pytest.fixture
def admin_http(admin_session):
    """로그인을 마친 관리자 클라이언트."""
    return admin_session()["http"]


@pytest.fixture
def documents(app):
    """자료실에 공개 문서 두 건을 넣는다(실제 파일은 samples/library에 있다)."""
    rows = [
        SiteDocument(
            title="본인확인 연동 규격 v2",
            summary="요청 서명 방식과 두 가지 연동 방식을 정리했습니다.",
            category="규격",
            filename="연동규격서_v2.md",
            size_bytes=783,
            published_on=date(2026, 11, 18),
        ),
        SiteDocument(
            title="서비스 소개서",
            summary="휴대폰 본인확인·신분증 진위확인·얼굴인증 안내입니다.",
            category="소개",
            filename="서비스소개서.txt",
            size_bytes=499,
            published_on=date(2026, 11, 10),
        ),
    ]
    db.session.add_all(rows)
    db.session.commit()
    return rows


def csrf_of(client, path: str) -> str:
    html = client.get(path).get_data(as_text=True)
    found = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert found
    return found.group(1)


def submit_inquiry(client, **overrides):
    data = {
        "csrf_token": csrf_of(client, "/support"),
        "kind": "서비스 연동 문의",
        "company": "가상거래소",
        "manager": "홍길동",
        "email": "contact@example.invalid",
        "message": "본인확인 연동 절차와 일정을 알고 싶습니다.",
    }
    data.update(overrides)
    return client.post("/support", data=data)


# ---------------------------------------------------------------- 문의 저장


def test_inquiry_is_stored_with_a_receipt_number(client, app):
    response = submit_inquiry(client)
    assert response.status_code == 200

    row = db.session.scalars(db.select(SiteInquiry)).one()
    assert row.company == "가상거래소"
    assert row.status == "RECEIVED"
    assert row.receipt_no in response.get_data(as_text=True)
    assert row.ip  # 접수 IP를 남긴다


def test_the_reply_page_does_not_echo_the_contact_details(client):
    html = submit_inquiry(client).get_data(as_text=True)
    assert "contact@example.invalid" not in html


def test_a_rejected_inquiry_is_not_stored(client):
    assert submit_inquiry(client, email="형식오류").status_code == 400
    assert db.session.scalars(db.select(SiteInquiry)).all() == []


# ---------------------------------------------------------------- 자료실


def test_library_lists_documents(client, documents):
    html = client.get(LIBRARY).get_data(as_text=True)
    assert "본인확인 연동 규격 v2" in html
    assert "서비스 소개서" in html


def test_download_sends_the_file(client, documents):
    response = client.get(DOWNLOAD, query_string={"doc": documents[0].id})
    assert response.status_code == 200
    assert "연동 규격 v2" in response.get_data(as_text=True)
    db.session.expire_all()
    assert db.session.get(SiteDocument, documents[0].id).downloads == 1


def test_unknown_document_is_404(client, documents):
    assert client.get(DOWNLOAD, query_string={"doc": 99999}).status_code == 404
    assert client.get(DOWNLOAD, query_string={"doc": "abc"}).status_code == 404
    assert client.get(DOWNLOAD).status_code == 404


def test_library_search(client, documents):
    html = client.get(LIBRARY, query_string={"q": "규격"}).get_data(as_text=True)
    assert "본인확인 연동 규격 v2" in html
    assert "서비스 소개서" not in html


# ------------------------------------------------- VULN_W01 (SQL 인젝션)


def test_w01_search_is_bound_by_default(client, documents):
    """양호: 검색어는 바인딩 파라미터다. 따옴표를 넣어도 그냥 검색어로 취급된다."""
    response = client.get(LIBRARY, query_string={"q": "' OR '1'='1"})
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "검색 결과 0건" in html
    assert "본인확인 연동 규격 v2" not in html


def test_w01_search_is_injectable_when_enabled(client, documents, enable_vuln):
    """취약: 문자열 연결이라 조건을 참으로 만들어 전체를 꺼낼 수 있다."""
    enable_vuln("VULN_W01")
    response = client.get(LIBRARY, query_string={"q": "' OR '1'='1"})
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "본인확인 연동 규격 v2" in html and "서비스 소개서" in html
    assert "검색 결과 2건" in html


def test_w01_does_not_touch_the_rest_of_the_site(client, documents, enable_vuln):
    """경계: 플래그는 자료실 검색에만 붙는다. 공지 검색은 그대로 고정 데이터다."""
    enable_vuln("VULN_W01")
    html = client.get("/notices", query_string={"q": "' OR '1'='1"}).get_data(as_text=True)
    assert "검색 결과가 없습니다" in html


# ------------------------------------------------- VULN_W05 (경로 조작)


def test_w05_file_parameter_is_ignored_by_default(client, documents):
    """양호: 요청의 file 값은 보지 않는다. doc(id)로만 찾는다."""
    response = client.get(DOWNLOAD, query_string={"file": "../../instance/dev_secrets.json"})
    assert response.status_code == 404


def test_w05_filename_cannot_hold_a_path(app, documents):
    """양호: 경로 구분자가 들어간 파일 이름은 DB가 거부한다(CHECK)."""
    import sqlalchemy.exc

    db.session.add(
        SiteDocument(
            title="나쁜 것",
            filename="../../instance/dev_secrets.json",
            size_bytes=1,
            published_on=date(2026, 11, 18),
        )
    )
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_w05_a_missing_file_is_404(client, documents):
    """양호: DB에만 있고 실제 파일이 없으면 내려주지 않는다."""
    documents[0].filename = "없는문서.txt"
    db.session.commit()
    assert client.get(DOWNLOAD, query_string={"doc": documents[0].id}).status_code == 404


def test_w05_path_traversal_when_enabled(client, documents, enable_vuln, tmp_path, app):
    """취약: file 값을 그대로 경로에 붙여 자료실 밖 파일을 내려받는다."""
    enable_vuln("VULN_W05")
    secret = tmp_path / "secret.txt"
    secret.write_text("최상위 비밀", encoding="utf-8")
    app.config["LIBRARY_DIR"] = str(tmp_path / "library")
    (tmp_path / "library").mkdir()

    response = client.get(DOWNLOAD, query_string={"file": "../secret.txt"})
    assert response.status_code == 200
    assert "최상위 비밀" in response.get_data(as_text=True)


def test_w05_still_404s_for_a_file_that_does_not_exist(client, documents, enable_vuln):
    enable_vuln("VULN_W05")
    assert client.get(DOWNLOAD, query_string={"file": "../../없는파일"}).status_code == 404


# ------------------------------------------------- VULN_W02 (저장형 XSS)


PAYLOAD = "<script>alert(document.cookie)</script>"


@pytest.fixture
def stored_script(app):
    """스크립트가 들어간 문의가 이미 저장돼 있는 상태.

    폼으로 넣지 않고 바로 적재한다. 접수 경로는 위에서 따로 보고, 여기서는
    "저장된 값을 화면이 어떻게 내보내는가"만 본다.
    """
    row = SiteInquiry(
        receipt_no="IJ-20261125-ABCDEF",
        kind="기술 지원",
        company="가상거래소",
        manager="홍길동",
        email="contact@example.invalid",
        message=f"연동 문의입니다. {PAYLOAD}",
        ip="127.0.0.1",
    )
    db.session.add(row)
    db.session.commit()
    return row


def test_w02_public_pages_escape_the_payload(client, stored_script):
    """홈페이지는 문의 내용을 되돌려주지 않는다. 애초에 노출면이 아니다."""
    html = client.get("/support").get_data(as_text=True)
    assert PAYLOAD not in html


def test_w02_admin_detail_escapes_by_default(admin_http, stored_script):
    """양호: Jinja autoescape로 그대로 글자로 보인다."""
    response = admin_http.get(f"/admin/inquiries/{stored_script.id}")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert PAYLOAD not in html
    assert "&lt;script&gt;" in html


def test_w02_admin_detail_executes_when_enabled(admin_http, stored_script, enable_vuln):
    """취약: 관리자가 상세를 열면 저장된 스크립트가 그대로 나간다."""
    enable_vuln("VULN_W02")
    html = admin_http.get(f"/admin/inquiries/{stored_script.id}").get_data(as_text=True)
    assert PAYLOAD in html


def test_w02_admin_list_stays_escaped_either_way(admin_http, stored_script, enable_vuln):
    """경계: 플래그는 상세 화면만 바꾼다. 목록은 본문을 아예 출력하지 않는다."""
    enable_vuln("VULN_W02")
    html = admin_http.get("/admin/inquiries").get_data(as_text=True)
    assert "<script>" not in html


def test_admin_can_see_the_inquiry_list(admin_http, stored_script):
    html = admin_http.get("/admin/inquiries").get_data(as_text=True)
    assert stored_script.receipt_no in html
    assert "가상거래소" in html
