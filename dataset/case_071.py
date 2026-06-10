def load_data():
    return request.args.get("key")

user = load_data()
cursor.execute("SELECT * FROM accounts WHERE username = " + user)
