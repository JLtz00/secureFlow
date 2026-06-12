user = request.args.get("key")
cursor.execute("SELECT * FROM accounts WHERE username = " + user)
