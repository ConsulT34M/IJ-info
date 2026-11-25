"""verifications.mode 추가 (D87: 위탁사 화면 + 서버 간 API 경로)

Revision ID: 8a3f21c47d90
Revises: 57bfa2df16bf
Create Date: 2026-11-25 17:05:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '8a3f21c47d90'
down_revision = '57bfa2df16bf'
branch_labels = None
depends_on = None


CHECK_NAME = "ck_verifications_mode"
CHECK_SQL = "mode IN ('REDIRECT', 'DIRECT')"


def upgrade():
    # 기존 건은 전부 인증창 방식이므로 REDIRECT로 채운다.
    with op.batch_alter_table('verifications', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('mode', sa.String(length=10), nullable=False, server_default='REDIRECT')
        )
        batch_op.create_check_constraint(CHECK_NAME, CHECK_SQL)
    # 기본값은 애플리케이션이 정하므로 DB server_default는 떼어 둔다.
    with op.batch_alter_table('verifications', schema=None) as batch_op:
        batch_op.alter_column('mode', server_default=None)


def downgrade():
    with op.batch_alter_table('verifications', schema=None) as batch_op:
        batch_op.drop_constraint(CHECK_NAME, type_='check')
        batch_op.drop_column('mode')
