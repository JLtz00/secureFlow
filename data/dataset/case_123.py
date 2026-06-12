raw = input("key")
param = sanitize(raw)
cursor.execute("SELECT * FROM accounts WHERE username = " + param)
