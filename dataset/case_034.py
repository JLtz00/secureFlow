entry = request.form.get("key")
cursor.execute("SELECT * FROM accounts WHERE username = " + entry)
