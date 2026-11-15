def search(cur, request):
    return cur.execute("SELECT * FROM notes WHERE title LIKE '%" + request.args["q"] + "%'")
