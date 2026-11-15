from alembic import op

revision = "0007"
down_revision = "0006"


def upgrade():
    conn = op.get_bind()
    table = "accounts"
    conn.execute(f"ALTER TABLE {table} ADD COLUMN flags INTEGER DEFAULT 0")
