def search(cursor, request):
    QUERY = request.args["q"]
    return cursor.execute("SELECT * FROM notes WHERE body LIKE '%" + QUERY + "%'")
