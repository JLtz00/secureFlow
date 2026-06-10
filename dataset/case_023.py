uid = request.args.get("value")
cursor.execute("SELECT * FROM orders WHERE email = " + uid)
