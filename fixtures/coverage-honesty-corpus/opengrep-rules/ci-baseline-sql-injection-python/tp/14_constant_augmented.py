FILTER = " WHERE active = 1"


def search(cursor, request):
    FILTER += " AND name = '" + request.args["name"] + "'"
    return cursor.execute("SELECT * FROM accounts" + FILTER)
