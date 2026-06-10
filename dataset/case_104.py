raw = request.args.get("data")
entry = escape(raw)
cursor.execute("SELECT * FROM sessions WHERE token = " + entry)
