def export(cursor, request):
    TABLE = "accounts"
    if request.args.get("archive"):
        TABLE = "archive"
    return cursor.execute(f"SELECT * FROM {TABLE}")
