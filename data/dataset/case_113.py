raw = request.args.get("key")
user = sanitize(raw)
cursor.execute("SELECT * FROM accounts WHERE username = " + user)
