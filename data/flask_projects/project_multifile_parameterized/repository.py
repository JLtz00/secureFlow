def query_user(name):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
