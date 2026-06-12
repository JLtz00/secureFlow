param = request.form.get("key")
cursor.execute("SELECT * FROM accounts WHERE username = " + param)
