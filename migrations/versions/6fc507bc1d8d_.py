"""empty message

Revision ID: 6fc507bc1d8d
Revises: 392595b3371c
Create Date: 2021-09-03 18:09:03.874518

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6fc507bc1d8d'
down_revision = '392595b3371c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('jwt_token', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'jwt_token')
    # ### end Alembic commands ###