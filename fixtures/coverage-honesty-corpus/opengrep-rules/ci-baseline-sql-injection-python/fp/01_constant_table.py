TABLE = "accounts"
ORDER = "created_at"


def recent(cur):
    cur.execute(f"SELECT id, name FROM {TABLE} ORDER BY {ORDER} DESC")
    cur.execute("SELECT COUNT(*) FROM %s" % (TABLE,))
    cur.execute("SELECT COUNT(*) FROM " + TABLE)
    return cur.fetchall()
