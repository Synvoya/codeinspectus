TABLE = "accounts"


def by_owner(cur, owner):
    return cur.execute("SELECT * FROM %s WHERE owner = '%s'" % (TABLE, owner))
