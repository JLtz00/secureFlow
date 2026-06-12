def load_data():
    return input("key")

name = load_data()
cursor.execute("SELECT * FROM accounts WHERE username = " + name)
