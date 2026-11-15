TABLE = "accounts"


def export(cursor, request):
    if request.args.get("table"):
        TABLE = request.args["table"]
    return cursor.execute(f"SELECT * FROM {TABLE}")
