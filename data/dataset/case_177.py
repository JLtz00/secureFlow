uid = input("key")
flag = 1
if flag:
    query = uid
cursor.execute("SELECT * FROM accounts WHERE username = " + query)
