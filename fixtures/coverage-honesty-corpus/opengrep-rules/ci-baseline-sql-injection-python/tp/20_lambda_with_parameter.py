COLUMN = "name"


def report(cursor, request):
    query = lambda c: c.execute(f"SELECT {COLUMN} FROM accounts")
    COLUMN = request.args["column"]
    return query(cursor)
