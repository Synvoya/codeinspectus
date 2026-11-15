TABLE = "accounts"


def export_all(cursor, request):
    for TABLE in request.args.getlist("tables"):
        cursor.execute(f"SELECT * FROM {TABLE}")
