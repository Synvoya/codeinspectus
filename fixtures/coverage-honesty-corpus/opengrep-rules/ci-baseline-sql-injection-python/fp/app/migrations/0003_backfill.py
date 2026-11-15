def forwards(cursor, schema):
    cursor.execute("UPDATE %s.accounts SET flags = 0 WHERE flags IS NULL" % schema)
