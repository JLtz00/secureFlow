raw = request.args.get("param")
name = sanitize(raw)
cursor.execute("SELECT * FROM products WHERE name = " + name)
