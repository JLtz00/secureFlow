def get_param():
    return input("field")

entry = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + entry)
