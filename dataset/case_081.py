def load_data():
    return input("key")

param = load_data()
cursor.execute("SELECT * FROM accounts WHERE username = " + param)
