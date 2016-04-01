"""empty message

Revision ID: f7340e5d5d4
Revises: 4600bfa86e8
Create Date: 2016-03-31 16:37:00.533270

"""

# revision identifiers, used by Alembic.
revision = 'f7340e5d5d4'
down_revision = '4600bfa86e8'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('confirmed', sa.Boolean(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'confirmed')
    ### end Alembic commands ###
