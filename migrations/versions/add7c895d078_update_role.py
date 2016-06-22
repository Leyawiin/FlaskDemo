"""update Role

Revision ID: add7c895d078
Revises: f7340e5d5d4
Create Date: 2016-06-20 22:24:37.829693

"""

# revision identifiers, used by Alembic.
revision = 'add7c895d078'
down_revision = 'f7340e5d5d4'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('roles', sa.Column('default', sa.Boolean(), nullable=True))
    op.add_column('roles', sa.Column('permission', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_roles_default'), 'roles', ['default'], unique=False)
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_roles_default'), table_name='roles')
    op.drop_column('roles', 'permission')
    op.drop_column('roles', 'default')
    ### end Alembic commands ###