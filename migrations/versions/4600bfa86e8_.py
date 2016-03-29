"""empty message

Revision ID: 4600bfa86e8
Revises: e38be5b6833
Create Date: 2016-03-30 00:27:47.006845

"""

# revision identifiers, used by Alembic.
revision = '4600bfa86e8'
down_revision = 'e38be5b6833'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
 #   op.drop_column('users', 'test')
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('test')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('test', sa.VARCHAR(length=128), nullable=True))
    ### end Alembic commands ###
