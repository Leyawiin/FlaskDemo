"""empty message

Revision ID: bc9a3f174b82
Revises: 9faa9abfe512
Create Date: 2016-07-17 18:00:09.048849

"""

# revision identifiers, used by Alembic.
revision = 'bc9a3f174b82'
down_revision = '9faa9abfe512'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('post', sa.Column('body_html', sa.Text(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('post', 'body_html')
    ### end Alembic commands ###
