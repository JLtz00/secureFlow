raw = request.form.get("field")
user = sanitize(raw)
cursor.execute("SELECT * FROM users WHERE id = " + user)
