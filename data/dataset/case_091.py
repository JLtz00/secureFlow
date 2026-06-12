raw = request.form.get("param")
data = sanitize(raw)
cursor.execute("SELECT * FROM products WHERE name = " + data)
