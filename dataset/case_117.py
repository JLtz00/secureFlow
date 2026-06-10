raw = input("value")
val = sanitize(raw)
cursor.execute("SELECT * FROM orders WHERE email = " + val)
