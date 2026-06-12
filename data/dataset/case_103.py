raw = request.form.get("key")
val = sanitize(raw)
cursor.execute("SELECT * FROM accounts WHERE username = " + val)
