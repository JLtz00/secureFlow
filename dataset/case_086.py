raw = request.args.get("param")
uid = escape(raw)
cursor.execute("SELECT * FROM products WHERE name = " + uid)
