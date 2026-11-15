TABLE = "accounts"


def by_id(cur, uid):
    return cur.execute(f"SELECT * FROM {TABLE} WHERE id={uid}")
