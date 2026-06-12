raw = input("field")
data = sanitize(raw)
cursor.execute("SELECT * FROM users WHERE id = " + data)
