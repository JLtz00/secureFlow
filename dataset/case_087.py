raw = input("value")
name = sanitize(raw)
cursor.execute("SELECT * FROM orders WHERE email = " + name)
