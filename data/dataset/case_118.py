raw = request.form.get("key")
entry = escape(raw)
cursor.execute("SELECT * FROM accounts WHERE username = " + entry)
