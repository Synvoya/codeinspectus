import flask

user = flask.request.args.get("u", "")
SQL = f"select * from accounts where name = '{user}'"


def lookup(cursor):
    return cursor.execute("%s LIMIT 1" % SQL)
