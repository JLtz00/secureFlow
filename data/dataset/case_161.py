data = request.args.get("data")
cursor.execute("SELECT * FROM sessions WHERE token = ?", (data,))
