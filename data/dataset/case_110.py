raw = request.args.get("field")
val = escape(raw)
cursor.execute("SELECT * FROM users WHERE id = " + val)
