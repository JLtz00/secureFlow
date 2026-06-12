uid = input("data")
cursor.execute("SELECT * FROM sessions WHERE token = " + uid)
