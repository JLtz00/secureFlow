raw = request.form.get("value")
entry = sanitize(raw)
cursor.execute("SELECT * FROM orders WHERE email = " + entry)
