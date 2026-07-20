def query_user(name):
    query = "SELECT * FROM users WHERE name = " + name
    return db.session.execute(query)
