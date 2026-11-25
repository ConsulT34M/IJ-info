"""(주)인증정보평가 회사 홈페이지.

공개 노출면이라 개인정보를 다루지 않는다. 콘텐츠는 app/site/content.py의
고정 데이터이고, DB도 서버 세션도 쓰지 않는다(D83).

문의는 저장하지 않고 접수번호만 돌려준다(D84). 실습 환경에 개인정보를
남기지 않으려는 선택이다.
"""

from __future__ import annotations

import re
import secrets as py_secrets
from pathlib import Path

import sqlalchemy as sa
from flask import Blueprint, abort, current_app, render_template, request, send_file

from app.common.client_ip import client_ip
from app.common.timeutil import now_utc, to_kst
from app.models import SiteDocument, SiteInquiry, db
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
    db.session.add(
        SiteInquiry(
            receipt_no=receipt_no,
            kind=form["kind"],
            company=form["company"],
            manager=form["manager"],
            email=form["email"],
            message=form["message"],
            ip=client_ip(),
        )
    )
    db.session.commit()
    current_app.logger.info("문의 접수: receipt_no=%s kind=%s", receipt_no, form["kind"])
    return render_template(
        "site/support_done.html", receipt_no=receipt_no, kind=form["kind"], active="support"
    )


@bp.get("/library")
def library():
    """자료실 목록. 검색어(q)로 제목·설명을 찾는다."""
    keyword = (request.args.get("q") or "").strip()[:60]
    documents = _search_documents(keyword)
    return render_template(
        "site/library.html", documents=documents, keyword=keyword, active="library"
    )


@bp.get("/library/download")
def library_download():
    """자료실 파일 내려받기.

    양호: 저장소의 id로만 찾고, 실제 경로는 서버가 만든다. 요청에 들어온 이름은 쓰지 않는다.
    VULN_W05를 켜면 요청의 file 값을 그대로 경로에 붙인다(경로 조작, D90).
    """
    library_dir = _library_dir()

    if current_app.config.get("VULN_W05"):
        requested = request.args.get("file")
        if requested:
            target = library_dir / requested
            if not target.is_file():
                abort(404)
            current_app.logger.warning("자료실 경로 조작 경로 사용: file=%s", requested)
            return send_file(target, as_attachment=True, download_name=Path(requested).name)

    document = db.session.get(SiteDocument, _document_id(request.args.get("doc")))
    if document is None:
        abort(404)

    target = library_dir / document.filename
    if not _inside(target, library_dir) or not target.is_file():
        current_app.logger.error("자료실 파일이 없다: id=%s", document.id)
        abort(404)

    document.downloads += 1
    db.session.commit()
    return send_file(target, as_attachment=True, download_name=document.filename)


@bp.get("/privacy")
def privacy():
    """개인정보 처리방침."""
    return render_template("site/privacy.html", company=content.COMPANY, active="privacy")


@bp.get("/demo")
def demo():
    """실습 안내. 인증창은 위탁사 요청(IA-01)으로만 열린다."""
    return render_template("site/demo.html", active="demo")


def _library_dir() -> Path:
    """자료실 폴더의 절대 경로."""
    configured = Path(current_app.config["LIBRARY_DIR"])
    if not configured.is_absolute():
        configured = Path(current_app.root_path).parent / configured
    return configured.resolve()


def _inside(target: Path, parent: Path) -> bool:
    """경로가 자료실 폴더 안인지 확인한다(W-05)."""
    try:
        return parent in target.resolve().parents
    except OSError:
        return False


def _document_id(raw: str | None) -> int:
    try:
        return int(raw or 0)
    except ValueError:
        abort(404)


def _search_documents(keyword: str) -> list[SiteDocument]:
    """자료실 검색.

    양호: 바인딩 파라미터로 넘긴다(W-01).
    VULN_W01을 켜면 검색어를 SQL 문자열에 그대로 이어 붙인다(SQL 인젝션, D90).
    """
    if not keyword:
        return list(
            db.session.scalars(db.select(SiteDocument).order_by(SiteDocument.published_on.desc()))
        )

    if current_app.config.get("VULN_W01"):
        current_app.logger.warning("자료실 검색을 문자열 연결로 수행한다: q=%s", keyword)
        statement = sa.text(
            "SELECT * FROM site_documents"
            f" WHERE title LIKE '%{keyword}%' OR summary LIKE '%{keyword}%'"
            " ORDER BY published_on DESC"
        )
        return list(db.session.scalars(db.select(SiteDocument).from_statement(statement)))

    pattern = f"%{keyword}%"
    return list(
        db.session.scalars(
            db.select(SiteDocument)
            .where(sa.or_(SiteDocument.title.ilike(pattern), SiteDocument.summary.ilike(pattern)))
            .order_by(SiteDocument.published_on.desc())
        )
    )


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
