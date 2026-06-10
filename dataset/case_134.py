user = request.args.get("value")
cursor.execute("SELECT * FROM orders WHERE email = ?", (user,))
