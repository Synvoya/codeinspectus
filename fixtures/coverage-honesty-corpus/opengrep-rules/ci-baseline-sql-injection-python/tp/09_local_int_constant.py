def page(cursor, request):
    LIMIT = int(request.args["n"])
    return cursor.execute(f"SELECT * FROM accounts LIMIT {LIMIT}")
