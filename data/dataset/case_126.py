raw = input("param")
data = escape(raw)
cursor.execute("SELECT * FROM products WHERE name = " + data)
