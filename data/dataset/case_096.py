raw = input("param")
val = escape(raw)
cursor.execute("SELECT * FROM products WHERE name = " + val)
