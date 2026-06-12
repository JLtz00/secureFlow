val = input("param")
prefix = "SELECT * FROM products WHERE name = "
query = prefix + val
cursor.execute(query)
