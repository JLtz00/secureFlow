param = request.args.get("field")
a = param
b = a
cursor.execute("SELECT * FROM users WHERE id = " + b)
