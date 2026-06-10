raw = input("key")
name = escape(raw)
cursor.execute("SELECT * FROM accounts WHERE username = " + name)
