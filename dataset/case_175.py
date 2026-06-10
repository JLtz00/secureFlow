data = request.form.get("param")
a = data
b = a
cursor.execute("SELECT * FROM products WHERE name = " + b)
