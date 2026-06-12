name = input("value")
a = name
b = a
cursor.execute("SELECT * FROM orders WHERE email = " + b)
