val = request.form.get("data")
cursor.execute("SELECT * FROM sessions WHERE token = ?", (val,))
