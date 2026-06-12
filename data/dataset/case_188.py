entry = request.args.get("data")
prefix = "SELECT * FROM sessions WHERE token = "
query = prefix + entry
cursor.execute(query)
