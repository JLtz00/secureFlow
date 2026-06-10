user = request.form.get("param")
cursor.execute("SELECT * FROM products WHERE name = ?", (user,))
