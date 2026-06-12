data = request.form.get("value")
prefix = "SELECT * FROM orders WHERE email = "
query = prefix + data
cursor.execute(query)
