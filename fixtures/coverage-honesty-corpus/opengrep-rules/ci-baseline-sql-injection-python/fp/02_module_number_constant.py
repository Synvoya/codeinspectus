TABLE = "users"
PAGE_SIZE = 50


def first_page(cursor):
    return cursor.execute(f"SELECT * FROM {TABLE} LIMIT {PAGE_SIZE}")
