name = request.form.get("data")
cursor.execute("SELECT * FROM sessions WHERE token = " + name)
