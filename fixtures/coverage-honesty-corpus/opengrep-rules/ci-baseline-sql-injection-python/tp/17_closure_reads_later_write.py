TABLE = "accounts"


def export(cursor, request):
    def run():
        return cursor.execute(f"SELECT * FROM {TABLE}")

    TABLE = request.args["table"]
    return run()
