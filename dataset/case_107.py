raw = request.args.get("value")
uid = sanitize(raw)
cursor.execute("SELECT * FROM orders WHERE email = " + uid)
