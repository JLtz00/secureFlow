data = request.form.get("value")
cursor.execute("SELECT * FROM orders WHERE email = " + data)
