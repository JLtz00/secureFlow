raw = request.form.get("data")
name = escape(raw)
cursor.execute("SELECT * FROM sessions WHERE token = " + name)
