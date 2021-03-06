"""empty message

Revision ID: f6f04621ff24
Revises: 6fc507bc1d8d
Create Date: 2021-09-07 07:25:36.164196

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f6f04621ff24'
down_revision = '6fc507bc1d8d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('otp',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('code', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
    sa.Column('expiry', sa.DateTime(), nullable=True),
    sa.Column('verified', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('otp')
    # ### end Alembic commands ###
