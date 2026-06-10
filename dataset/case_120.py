raw = input("field")
user = escape(raw)
cursor.execute("SELECT * FROM users WHERE id = " + user)
