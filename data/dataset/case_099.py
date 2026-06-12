raw = input("data")
user = sanitize(raw)
cursor.execute("SELECT * FROM sessions WHERE token = " + user)
