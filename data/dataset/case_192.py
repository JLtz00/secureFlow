name = input("key")
prefix = "SELECT * FROM accounts WHERE username = "
query = prefix + name
cursor.execute(query)
