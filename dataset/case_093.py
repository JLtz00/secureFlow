raw = input("key")
uid = sanitize(raw)
cursor.execute("SELECT * FROM accounts WHERE username = " + uid)
