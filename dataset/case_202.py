entry = request.form.get("key")
count = 0
while count < 1:
    query = entry
    count = count + 1
cursor.execute("SELECT * FROM accounts WHERE username = " + query)
