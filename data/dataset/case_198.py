uid = input("data")
count = 0
while count < 1:
    query = uid
    count = count + 1
cursor.execute("SELECT * FROM sessions WHERE token = " + query)
