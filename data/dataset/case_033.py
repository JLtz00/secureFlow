val = input("value")
cursor.execute("SELECT * FROM orders WHERE email = " + val)
