param = request.form.get("data")
flag = 1
if flag:
    query = param
cursor.execute("SELECT * FROM sessions WHERE token = " + query)
