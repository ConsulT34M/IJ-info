"""(주)인증정보평가 회사 홈페이지.

공개 노출면이라 개인정보를 다루지 않는다. 콘텐츠는 app/site/content.py의
고정 데이터이고, DB도 서버 세션도 쓰지 않는다(D83).

문의는 저장하지 않고 접수번호만 돌려준다(D84). 실습 환경에 개인정보를
남기지 않으려는 선택이다.
"""

from __future__ import annotations

import re
import secrets as py_secrets

from flask import Blueprint, abort, render_template, request

from app.common.timeutil import now_utc, to_kst
from app.site import content

bp = Blueprint("site", __name__)

INQUIRY_KINDS = ["서비스 연동 문의", "기술 지원", "개인정보 열람·정정", "장애 신고", "기타"]

LIMITS = {"company": 80, "manager": 40, "email": 120, "message": 2000}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]{2,}$")


@bp.get("/")
def index():
    """메인 화면."""
    return render_template(
        "site/index.html",
        services=content.SERVICES,
        stats=content.STATS,
        notices=content.latest_notices(3),
        active="home",
    )


@bp.get("/about")
def about():
    """회사 소개."""
    return render_template(
        "site/about.html",
        history=content.HISTORY,
        certs=content.CERTS,
        active="about",
    )


@bp.get("/services")
def services():
    """서비스 소개."""
    return render_template("site/services.html", services=content.SERVICES, active="services")


@bp.get("/notices")
def notices():
    """공지사항 목록. 검색어(q)와 페이지(page)를 받는다."""
    keyword = (request.args.get("q") or "").strip()[:60]
    found = content.search_notices(keyword)
    per_page = content.NOTICES_PER_PAGE
    pages = max(1, -(-len(found) // per_page))
    page = _page_number(request.args.get("page"), pages)
    start = (page - 1) * per_page
    return render_template(
        "site/notices.html",
        notices=found[start : start + per_page],
        total=len(found),
        keyword=keyword,
        page=page,
        pages=pages,
        active="notices",
    )


@bp.get("/notices/<int:no>")
def notice_detail(no: int):
    """공지 상세. 없는 글은 404다."""
    notice = content.find_notice(no)
    if notice is None:
        abort(404)
    newer, older = content.neighbours(no)
    return render_template(
        "site/notice.html", notice=notice, newer=newer, older=older, active="notices"
    )


@bp.get("/support")
def support():
    """고객지원: FAQ와 문의 폼."""
    return render_template(
        "site/support.html",
        faqs=content.FAQS,
        kinds=INQUIRY_KINDS,
        form={},
        error=None,
        active="support",
    )


@bp.post("/support")
def support_submit():
    """문의 접수. 내용은 저장하지 않고 접수번호만 돌려준다(D84)."""
    form = {
        "kind": (request.form.get("kind") or "").strip(),
        "company": (request.form.get("company") or "").strip(),
        "manager": (request.form.get("manager") or "").strip(),
        "email": (request.form.get("email") or "").strip(),
        "message": (request.form.get("message") or "").strip(),
    }
    error = _validate_inquiry(form)
    if error:
        return (
            render_template(
                "site/support.html",
                faqs=content.FAQS,
                kinds=INQUIRY_KINDS,
                form=form,
                error=error,
                active="support",
            ),
            400,
        )

    receipt_no = f"IJ-{to_kst(now_utc()):%Y%m%d}-{py_secrets.token_hex(3).upper()}"
    return render_template(
        "site/support_done.html", receipt_no=receipt_no, kind=form["kind"], active="support"
    )


@bp.get("/privacy")
def privacy():
    """개인정보 처리방침."""
    return render_template("site/privacy.html", company=content.COMPANY, active="privacy")


@bp.get("/demo")
def demo():
    """실습 안내. 인증창은 위탁사 요청(IA-01)으로만 열린다."""
    return render_template("site/demo.html", active="demo")


def _page_number(raw: str | None, pages: int) -> int:
    """잘못된 page 값은 1로 본다."""
    try:
        page = int(raw or 1)
    except ValueError:
        return 1
    return min(max(page, 1), pages)


def _validate_inquiry(form: dict) -> str | None:
    """문의 폼 검사. 통과하면 None."""
    if form["kind"] not in INQUIRY_KINDS:
        return "문의 유형을 선택해 주세요."
    for field, label in (("company", "회사명"), ("manager", "담당자명"), ("email", "이메일")):
        if not form[field]:
            return f"{label}을(를) 입력해 주세요."
        if len(form[field]) > LIMITS[field]:
            return f"{label}이(가) 너무 깁니다. {LIMITS[field]}자 이내로 입력해 주세요."
    if not EMAIL_RE.match(form["email"]):
        return "이메일 형식을 확인해 주세요."
    if len(form["message"]) < 10:
        return "문의 내용을 10자 이상 입력해 주세요."
    if len(form["message"]) > LIMITS["message"]:
        return f"문의 내용이 너무 깁니다. {LIMITS['message']}자 이내로 입력해 주세요."
    return None
