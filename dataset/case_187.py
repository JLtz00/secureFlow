val = request.form.get("key")
a = val
b = a
cursor.execute("SELECT * FROM accounts WHERE username = " + b)
