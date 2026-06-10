val = input("value")
flag = 1
if flag:
    query = val
cursor.execute("SELECT * FROM orders WHERE email = " + query)
