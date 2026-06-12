def obtain_val():
    return input("data")

uid = obtain_val()
cursor.execute("SELECT * FROM sessions WHERE token = " + uid)
