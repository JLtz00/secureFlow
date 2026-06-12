def get_param():
    return request.args.get("field")

entry = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + entry)
