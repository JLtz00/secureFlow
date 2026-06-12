def get_param():
    return input("field")

data = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + data)
