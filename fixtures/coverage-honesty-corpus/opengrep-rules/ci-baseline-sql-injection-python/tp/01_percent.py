def find(cur, uid):
    return cur.execute("SELECT * FROM users WHERE id = %s" % uid)
