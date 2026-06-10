raw = request.form.get("param")
uid = sanitize(raw)
cursor.execute("SELECT * FROM products WHERE name = " + uid)
