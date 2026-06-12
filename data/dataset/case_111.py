raw = input("param")
entry = sanitize(raw)
cursor.execute("SELECT * FROM products WHERE name = " + entry)
