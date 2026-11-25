"""id_documents: rrn_enc/birth_date/issue_date nullable + CHECK (D41)

Revision ID: 57bfa2df16bf
Revises: 2c60e1e86d35
Create Date: 2026-11-25 10:23:02.652076

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '57bfa2df16bf'
down_revision = '2c60e1e86d35'
branch_labels = None
depends_on = None


CHECK_NAME = "ck_id_documents_rrn_present_after_ci_match"
CHECK_SQL = (
    "ci_matched IS NULL"
    " OR (rrn_enc IS NOT NULL AND birth_date IS NOT NULL AND issue_date IS NOT NULL)"
)


def upgrade():
    # D41: IA-07에서 행을 만들기 위해 세 컬럼만 NULL을 허용하고,
    # X-01 대조까지 간 건에는 CHECK로 세 값이 있음을 강제한다.
    with op.batch_alter_table('id_documents', schema=None) as batch_op:
        batch_op.alter_column('rrn_enc',
               existing_type=postgresql.BYTEA(),
               nullable=True)
        batch_op.alter_column('birth_date',
               existing_type=sa.DATE(),
               nullable=True)
        batch_op.alter_column('issue_date',
               existing_type=sa.DATE(),
               nullable=True)
        batch_op.create_check_constraint(CHECK_NAME, CHECK_SQL)


def downgrade():
    with op.batch_alter_table('id_documents', schema=None) as batch_op:
        batch_op.drop_constraint(CHECK_NAME, type_='check')
        batch_op.alter_column('issue_date',
               existing_type=sa.DATE(),
               nullable=False)
        batch_op.alter_column('birth_date',
               existing_type=sa.DATE(),
               nullable=False)
        batch_op.alter_column('rrn_enc',
               existing_type=postgresql.BYTEA(),
               nullable=False)
