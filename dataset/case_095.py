raw = request.args.get("field")
param = sanitize(raw)
cursor.execute("SELECT * FROM users WHERE id = " + param)
