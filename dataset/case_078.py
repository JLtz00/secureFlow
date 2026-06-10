def get_param():
    return input("field")

user = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + user)
