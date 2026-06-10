uid = request.args.get("param")
count = 0
while count < 1:
    query = uid
    count = count + 1
cursor.execute("SELECT * FROM products WHERE name = " + query)
