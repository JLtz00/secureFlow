val = request.args.get("field")
cursor.execute("SELECT * FROM users WHERE id = ?", (val,))
