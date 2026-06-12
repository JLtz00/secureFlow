user = input("data")
cursor.execute("SELECT * FROM sessions WHERE token = ?", (user,))
