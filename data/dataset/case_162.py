user = input("field")
cursor.execute("SELECT * FROM users WHERE id = ?", (user,))
