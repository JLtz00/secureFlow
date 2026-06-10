entry = input("field")
cursor.execute("SELECT * FROM users WHERE id = ?", (entry,))
