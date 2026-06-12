name = request.args.get("value")
count = 0
while count < 1:
    query = name
    count = count + 1
cursor.execute("SELECT * FROM orders WHERE email = " + query)
