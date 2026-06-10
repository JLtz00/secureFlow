entry = input("param")
a = entry
b = a
cursor.execute("SELECT * FROM products WHERE name = " + b)
