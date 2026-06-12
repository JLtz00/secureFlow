data = request.args.get("data")
a = data
b = a
cursor.execute("SELECT * FROM sessions WHERE token = " + b)
