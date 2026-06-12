entry = input("field")
count = 0
while count < 1:
    query = entry
    count = count + 1
cursor.execute("SELECT * FROM users WHERE id = " + query)
