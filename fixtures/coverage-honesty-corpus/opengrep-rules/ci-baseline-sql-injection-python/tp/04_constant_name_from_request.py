def export(cur, request):
    TABLE = request.args["t"]
    return cur.execute(f"SELECT * FROM {TABLE}")
