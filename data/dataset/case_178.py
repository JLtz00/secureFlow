name = request.form.get("data")
count = 0
while count < 1:
    query = name
    count = count + 1
cursor.execute("SELECT * FROM sessions WHERE token = " + query)
