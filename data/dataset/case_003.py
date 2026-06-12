name = input("value")
cursor.execute("SELECT * FROM orders WHERE email = " + name)
