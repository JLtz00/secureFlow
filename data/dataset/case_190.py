user = request.form.get("param")
count = 0
while count < 1:
    query = user
    count = count + 1
cursor.execute("SELECT * FROM products WHERE name = " + query)
