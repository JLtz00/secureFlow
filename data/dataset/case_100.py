raw = request.form.get("field")
uid = escape(raw)
cursor.execute("SELECT * FROM users WHERE id = " + uid)
