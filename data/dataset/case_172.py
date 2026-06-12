param = request.form.get("key")
prefix = "SELECT * FROM accounts WHERE username = "
query = prefix + param
cursor.execute(query)
