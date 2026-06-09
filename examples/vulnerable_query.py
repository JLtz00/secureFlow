def build_query(user):
    query = "SELECT * FROM users WHERE name=" + user
    if user:
        return query
    return "SELECT * FROM users"


user = request.args.get("user")
query = build_query(user)
cursor.execute(query)
