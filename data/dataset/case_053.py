def get_param():
    return request.args.get("field")

param = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + param)
