raw = request.form.get("value")
data = escape(raw)
cursor.execute("SELECT * FROM orders WHERE email = " + data)
