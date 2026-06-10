raw = input("data")
uid = escape(raw)
cursor.execute("SELECT * FROM sessions WHERE token = " + uid)
