param = request.args.get("param")
prefix = "SELECT * FROM products WHERE name = "
query = prefix + param
cursor.execute(query)
