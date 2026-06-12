val = request.args.get("data")
flag = 1
if flag:
    query = val
cursor.execute("SELECT * FROM sessions WHERE token = " + query)
