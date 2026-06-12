param = input("key")
a = param
b = a
cursor.execute("SELECT * FROM accounts WHERE username = " + b)
