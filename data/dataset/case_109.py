raw = request.form.get("data")
param = sanitize(raw)
cursor.execute("SELECT * FROM sessions WHERE token = " + param)
