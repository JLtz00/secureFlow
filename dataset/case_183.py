user = input("data")
a = user
b = a
cursor.execute("SELECT * FROM sessions WHERE token = " + b)
