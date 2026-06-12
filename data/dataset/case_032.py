param = request.args.get("param")
cursor.execute("SELECT * FROM products WHERE name = " + param)
