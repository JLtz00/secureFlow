param = input("value")
cursor.execute("SELECT * FROM orders WHERE email = " + param)
