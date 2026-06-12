raw = input("value")
param = escape(raw)
cursor.execute("SELECT * FROM orders WHERE email = " + param)
