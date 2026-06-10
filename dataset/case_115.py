raw = request.form.get("field")
name = sanitize(raw)
cursor.execute("SELECT * FROM users WHERE id = " + name)
