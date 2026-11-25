"""위탁사(거래소)용 API Blueprint. CSRF 대신 HMAC 서명으로 보호한다."""

from app.api.routes import bp

# IA-21·IA-22(위탁사 화면 + 서버 간 경로)를 같은 Blueprint에 얹는다. routes 다음에 와야 한다.
from app.api import direct as _direct  # noqa: E402,F401

__all__ = ["bp"]
