user = request.args.get("key")
flag = 1
if flag:
    query = user
cursor.execute("SELECT * FROM accounts WHERE username = " + query)
