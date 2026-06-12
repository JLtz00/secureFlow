raw = request.args.get("value")
user = escape(raw)
cursor.execute("SELECT * FROM orders WHERE email = " + user)
