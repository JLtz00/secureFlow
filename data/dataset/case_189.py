data = input("field")
flag = 1
if flag:
    query = data
cursor.execute("SELECT * FROM users WHERE id = " + query)
