entry = request.form.get("value")
flag = 1
if flag:
    query = entry
cursor.execute("SELECT * FROM orders WHERE email = " + query)
