uid = request.args.get("value")
a = uid
b = a
cursor.execute("SELECT * FROM orders WHERE email = " + b)
