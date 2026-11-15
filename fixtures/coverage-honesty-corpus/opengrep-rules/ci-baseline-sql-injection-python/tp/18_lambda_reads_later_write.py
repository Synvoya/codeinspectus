TABLE = "accounts"


def export(cursor, request):
    run = lambda: cursor.execute("SELECT * FROM %s" % TABLE)
    TABLE = request.args["table"]
    return run()
