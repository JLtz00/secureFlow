raw = request.args.get("value")
name = escape(raw)
cursor.execute("SELECT * FROM orders WHERE email = " + name)
