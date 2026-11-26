"""E2E 재실행용: 번호별 60초 발송 제한(D11)만 푼다. 통제를 끄는 게 아니라 시계를 되감는다."""
from app import create_app
from app.models import TestPhone, db

app = create_app()
with app.app_context():
    count = db.session.query(TestPhone).update({TestPhone.next_issue_at: None})
    db.session.commit()
    print(f"발송 제한 초기화: {count}건")
