"""모의 진위확인(IA-13). HTTP 라우트 없이 앱 내부 함수 호출이다(D3).

공개된 조회 창구를 만들지 않기 위해 라우트를 두지 않는다. 대장에는 주민번호 원문이 아니라
HMAC 해시(키 `ekyc/mois-key`)만 들어 있다.
"""

from app.mock_mois.registry import verify

__all__ = ["verify"]
