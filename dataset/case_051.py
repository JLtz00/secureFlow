def load_data():
    return input("key")

uid = load_data()
cursor.execute("SELECT * FROM accounts WHERE username = " + uid)
