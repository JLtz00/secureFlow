user = request.form.get("field")
flag = 1
if flag:
    query = user
cursor.execute("SELECT * FROM users WHERE id = " + query)
