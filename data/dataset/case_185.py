name = request.args.get("param")
flag = 1
if flag:
    query = name
cursor.execute("SELECT * FROM products WHERE name = " + query)
