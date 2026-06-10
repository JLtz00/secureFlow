raw = request.args.get("data")
val = sanitize(raw)
cursor.execute("SELECT * FROM sessions WHERE token = " + val)
