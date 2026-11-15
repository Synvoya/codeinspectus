def by_table(cursor, TABLE):
    return cursor.execute(f"SELECT * FROM {TABLE}")
