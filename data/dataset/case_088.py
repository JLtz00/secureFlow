raw = request.form.get("key")
param = escape(raw)
cursor.execute("SELECT * FROM accounts WHERE username = " + param)
