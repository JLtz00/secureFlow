name = request.form.get("field")
cursor.execute("SELECT * FROM users WHERE id = ?", (name,))
