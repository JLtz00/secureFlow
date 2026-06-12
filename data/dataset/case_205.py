uid = request.form.get("param")
flag = 1
if flag:
    query = uid
cursor.execute("SELECT * FROM products WHERE name = " + query)
