name = request.form.get("field")
a = name
b = a
cursor.execute("SELECT * FROM users WHERE id = " + b)
