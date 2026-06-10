uid = request.form.get("field")
prefix = "SELECT * FROM users WHERE id = "
query = prefix + uid
cursor.execute(query)
