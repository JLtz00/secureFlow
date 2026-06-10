def get_param():
    return request.args.get("field")

val = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + val)
