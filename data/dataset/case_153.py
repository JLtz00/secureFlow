entry = input("param")
cursor.execute("SELECT * FROM products WHERE name = ?", (entry,))
