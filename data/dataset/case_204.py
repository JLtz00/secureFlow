user = input("field")
prefix = "SELECT * FROM users WHERE id = "
query = prefix + user
cursor.execute(query)
