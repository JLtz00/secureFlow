raw = request.args.get("key")
data = escape(raw)
cursor.execute("SELECT * FROM accounts WHERE username = " + data)
