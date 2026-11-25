"""site_inquiries · site_documents 추가 (D90: 홈페이지 문의 저장·자료실)

Revision ID: b17c40e9d2a5
Revises: 8a3f21c47d90
Create Date: 2026-11-25 22:20:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b17c40e9d2a5'
down_revision = '8a3f21c47d90'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'site_inquiries',
        sa.Column('id', sa.BigInteger().with_variant(sa.Integer, 'sqlite'),
                  autoincrement=True, nullable=False),
        sa.Column('receipt_no', sa.String(length=24), nullable=False),
        sa.Column('kind', sa.String(length=30), nullable=False),
        sa.Column('company', sa.String(length=80), nullable=False),
        sa.Column('manager', sa.String(length=40), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('answer', sa.Text(), nullable=True),
        sa.Column('answered_at', sa.DateTime(), nullable=True),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("status IN ('RECEIVED', 'ANSWERED')", name='ck_site_inquiries_status'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('receipt_no'),
    )
    op.create_index('ix_site_inquiries_created', 'site_inquiries', ['created_at'])

    op.create_table(
        'site_documents',
        sa.Column('id', sa.BigInteger().with_variant(sa.Integer, 'sqlite'),
                  autoincrement=True, nullable=False),
        sa.Column('title', sa.String(length=120), nullable=False),
        sa.Column('summary', sa.String(length=300), nullable=False),
        sa.Column('category', sa.String(length=20), nullable=False),
        sa.Column('filename', sa.String(length=120), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('published_on', sa.Date(), nullable=False),
        sa.Column('downloads', sa.Integer(), nullable=False),
        # 파일 이름만 담는다. 경로 구분자가 들어오면 거부한다(W-05).
        sa.CheckConstraint(
            "filename NOT LIKE '%/%' AND filename NOT LIKE '%\\%' AND filename NOT LIKE '%..%'",
            name='ck_site_documents_filename_is_plain',
        ),
        sa.CheckConstraint('size_bytes >= 0', name='ck_site_documents_size'),
        sa.CheckConstraint('downloads >= 0', name='ck_site_documents_downloads'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('filename'),
    )


def downgrade():
    op.drop_table('site_documents')
    op.drop_index('ix_site_inquiries_created', table_name='site_inquiries')
    op.drop_table('site_inquiries')
