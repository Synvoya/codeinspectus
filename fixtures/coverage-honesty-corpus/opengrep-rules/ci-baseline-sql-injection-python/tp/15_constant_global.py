TABLE = "accounts"


def configure(request):
    global TABLE
    TABLE = request.args["table"]


def export(cursor):
    global TABLE
    return cursor.execute(f"SELECT * FROM {TABLE}")
