uid = request.form.get("param")
cursor.execute("SELECT * FROM products WHERE name = " + uid)
