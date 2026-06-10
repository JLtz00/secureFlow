user = request.args.get("value")
prefix = "SELECT * FROM orders WHERE email = "
query = prefix + user
cursor.execute(query)
