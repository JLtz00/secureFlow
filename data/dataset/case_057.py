def obtain_val():
    return input("data")

user = obtain_val()
cursor.execute("SELECT * FROM sessions WHERE token = " + user)
