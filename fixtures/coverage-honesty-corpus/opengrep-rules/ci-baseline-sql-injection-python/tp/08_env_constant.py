import os

SCHEMA = os.environ.get("APP_SCHEMA", "public")


def count(cursor):
    return cursor.execute("SELECT COUNT(*) FROM " + SCHEMA + ".accounts")
