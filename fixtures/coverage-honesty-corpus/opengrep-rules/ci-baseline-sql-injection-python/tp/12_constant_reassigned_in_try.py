TABLE = "accounts"


def export(cursor, request):
    try:
        TABLE = request.args["table"]
    except KeyError:
        pass
    return cursor.execute("SELECT * FROM " + TABLE)
