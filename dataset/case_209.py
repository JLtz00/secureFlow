entry = request.args.get("field")
flag = 1
if flag:
    query = entry
cursor.execute("SELECT * FROM users WHERE id = " + query)
