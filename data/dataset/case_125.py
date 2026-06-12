raw = request.args.get("field")
entry = sanitize(raw)
cursor.execute("SELECT * FROM users WHERE id = " + entry)
