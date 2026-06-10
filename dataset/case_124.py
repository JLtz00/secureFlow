raw = request.form.get("data")
val = escape(raw)
cursor.execute("SELECT * FROM sessions WHERE token = " + val)
