param = input("value")
count = 0
while count < 1:
    query = param
    count = count + 1
cursor.execute("SELECT * FROM orders WHERE email = " + query)
