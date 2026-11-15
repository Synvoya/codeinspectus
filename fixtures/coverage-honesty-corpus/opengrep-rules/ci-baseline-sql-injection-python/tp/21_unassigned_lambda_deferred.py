COLUMN = "name"


def report(cursor, request, background_tasks):
    background_tasks.add_task(lambda: cursor.execute(f"SELECT {COLUMN} FROM accounts"))
    COLUMN = request.args["column"]
