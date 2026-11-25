"""회사 홈페이지(공개 화면) 테스트.

공개 노출면이라 개인정보를 다루지 않는다. 여기서는 (1) 화면이 떠야 하는 것,
(2) 보안 헤더와 CSP를 깨지 않는 것, (3) 입력값이 그대로 HTML에 들어가지 않는 것을 본다.
"""

from __future__ import annotations

import re

import pytest

from app.site import content

PUBLIC_PATHS = [
    "/",
    "/about",
    "/services",
    "/notices",
    "/support",
    "/privacy",
    "/demo",
]


def csrf_token_of(client, path: str = "/support") -> str:
    """화면에 박힌 csrf_token 값을 꺼낸다."""
    html = client.get(path).get_data(as_text=True)
    found = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert found, "csrf_token이 폼에 없다"
    return found.group(1)


@pytest.mark.parametrize("path", PUBLIC_PATHS)
def test_public_pages_render(client, path):
    response = client.get(path)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "인증정보평가" in html
    assert "실습용 가상 사이트" in html  # 실제 회사가 아니라는 고지


@pytest.mark.parametrize("path", PUBLIC_PATHS)
def test_public_pages_keep_security_headers(client, path):
    """공개 화면도 CSP·보안 헤더를 그대로 받는다."""
    response = client.get(path)
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.parametrize("path", PUBLIC_PATHS)
def test_public_pages_have_no_inline_style_or_script(client, path):
    """CSP에 'unsafe-inline'이 없으므로 inline style·script를 쓰면 화면이 깨진다."""
    html = client.get(path).get_data(as_text=True)
    assert 'style="' not in html
    assert "<style" not in html
    assert "<script" not in html


def test_home_shows_latest_notices(client):
    html = client.get("/").get_data(as_text=True)
    for notice in content.latest_notices(3):
        assert notice["title"] in html


def test_logo_is_served(client):
    response = client.get("/static/site/logo-mark.svg")
    assert response.status_code == 200
    assert "svg" in response.headers["Content-Type"]


def test_browsing_the_site_does_not_create_a_session(client):
    """공개 화면은 서버 세션을 만들지 않는다. 쿠키가 생기지 않아야 한다."""
    response = client.get("/")
    assert "Set-Cookie" not in response.headers


# ---------------------------------------------------------------- 공지사항


def test_notice_list_is_paged(client):
    html = client.get("/notices").get_data(as_text=True)
    assert f"전체 {len(content.NOTICES)}건" in html
    first_page = content.NOTICES[: content.NOTICES_PER_PAGE]
    assert content.NOTICES[-1]["title"] not in html  # 마지막 글은 다음 페이지에 있다
    for notice in first_page:
        assert notice["title"] in html


def test_notice_list_second_page(client):
    html = client.get("/notices?page=2").get_data(as_text=True)
    assert content.NOTICES[-1]["title"] in html


@pytest.mark.parametrize("page", ["0", "-3", "999", "abc", "", "1e3"])
def test_notice_list_survives_a_bad_page_value(client, page):
    """page에 아무 값이 와도 500이 나지 않는다."""
    assert client.get(f"/notices?page={page}").status_code == 200


def test_notice_search_filters_the_list(client):
    html = client.get("/notices?q=점검").get_data(as_text=True)
    assert "정기 서비스 점검 안내" in html
    assert "위탁사 API Key 재발급 절차 안내" not in html


def test_notice_search_with_no_result(client):
    html = client.get("/notices?q=존재하지않는검색어").get_data(as_text=True)
    assert "검색 결과가 없습니다" in html


def test_notice_search_keyword_is_escaped(client):
    """검색어는 그대로 화면에 되돌려주므로 반사형 XSS가 되지 않는지 본다."""
    payload = '"><script>alert(1)</script>'
    html = client.get("/notices", query_string={"q": payload}).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_notice_detail(client):
    notice = content.NOTICES[0]
    html = client.get(f"/notices/{notice['no']}").get_data(as_text=True)
    assert notice["title"] in html
    assert notice["body"][0] in html


def test_unknown_notice_is_404(client):
    response = client.get("/notices/999999")
    assert response.status_code == 404
    assert "페이지를 찾을 수 없습니다" in response.get_data(as_text=True)


def test_unknown_path_shows_the_site_404(client):
    """없는 주소는 회사 사이트 모양의 404로 돌려준다. 내부 사정은 드러내지 않는다."""
    response = client.get("/존재하지-않는-경로")
    assert response.status_code == 404
    html = response.get_data(as_text=True)
    assert "페이지를 찾을 수 없습니다" in html
    assert "Traceback" not in html
    assert "Werkzeug" not in html


# ---------------------------------------------------------------- 문의 폼


def test_inquiry_requires_csrf(client):
    """CSRF 토큰이 없으면 거부한다(W-03)."""
    response = client.post(
        "/support",
        data={
            "kind": "서비스 연동 문의",
            "company": "가상거래소",
            "manager": "홍길동",
            "email": "a@example.invalid",
            "message": "연동 절차를 알고 싶다.",
        },
    )
    assert response.status_code == 400


def test_inquiry_succeeds_and_returns_a_receipt_number(client):
    token = csrf_token_of(client)
    response = client.post(
        "/support",
        data={
            "csrf_token": token,
            "kind": "서비스 연동 문의",
            "company": "가상거래소",
            "manager": "홍길동",
            "email": "contact@example.invalid",
            "message": "본인확인 연동 절차와 일정을 알고 싶다.",
        },
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert re.search(r"IJ-\d{8}-[0-9A-F]{6}", html)
    assert "저장하지 않습니다" in html
    # 문의 내용을 화면에 되돌려주지 않는다
    assert "contact@example.invalid" not in html


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("kind", "아무거나", "문의 유형을 선택해 주세요."),
        ("company", "", "회사명을(를) 입력해 주세요."),
        ("manager", "", "담당자명을(를) 입력해 주세요."),
        ("email", "골뱅이없음", "이메일 형식을 확인해 주세요."),
        ("message", "짧다", "문의 내용을 10자 이상 입력해 주세요."),
    ],
)
def test_inquiry_validation(client, field, value, expected):
    token = csrf_token_of(client)
    data = {
        "csrf_token": token,
        "kind": "기술 지원",
        "company": "가상거래소",
        "manager": "홍길동",
        "email": "contact@example.invalid",
        "message": "본인확인 연동 절차와 일정을 알고 싶다.",
    }
    data[field] = value
    response = client.post("/support", data=data)
    assert response.status_code == 400
    assert expected in response.get_data(as_text=True)


def test_inquiry_input_is_escaped_when_redisplayed(client):
    """잘못된 입력으로 되돌아올 때 입력값이 그대로 HTML에 박히지 않는다."""
    token = csrf_token_of(client)
    response = client.post(
        "/support",
        data={
            "csrf_token": token,
            "kind": "기술 지원",
            "company": '"><script>alert(1)</script>',
            "manager": "홍길동",
            "email": "형식오류",
            "message": "본인확인 연동 절차와 일정을 알고 싶다.",
        },
    )
    assert response.status_code == 400
    html = response.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------- 연결


def test_site_links_to_the_admin_console(client):
    """임직원 로그인 동선. 진단에서 관리자 화면을 찾는 출발점이다."""
    html = client.get("/").get_data(as_text=True)
    assert "/admin/login" in html


def test_site_does_not_expose_a_way_to_open_the_verify_window(client):
    """인증창은 위탁사 요청(IA-01)으로만 열린다. 홈페이지에 진입 링크가 없어야 한다."""
    for path in PUBLIC_PATHS:
        html = client.get(path).get_data(as_text=True)
        assert "/verify/start/" not in html
