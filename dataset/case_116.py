raw = request.args.get("param")
param = escape(raw)
cursor.execute("SELECT * FROM products WHERE name = " + param)
