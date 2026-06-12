val = request.args.get("field")
count = 0
while count < 1:
    query = val
    count = count + 1
cursor.execute("SELECT * FROM users WHERE id = " + query)
