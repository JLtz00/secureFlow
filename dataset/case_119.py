raw = request.args.get("data")
data = sanitize(raw)
cursor.execute("SELECT * FROM sessions WHERE token = " + data)
