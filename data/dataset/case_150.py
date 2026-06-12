name = input("key")
cursor.execute("SELECT * FROM accounts WHERE username = ?", (name,))
