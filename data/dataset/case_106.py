raw = request.form.get("param")
user = escape(raw)
cursor.execute("SELECT * FROM products WHERE name = " + user)
