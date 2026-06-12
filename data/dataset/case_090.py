raw = input("field")
entry = escape(raw)
cursor.execute("SELECT * FROM users WHERE id = " + entry)
