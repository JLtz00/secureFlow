def load_data():
    return request.args.get("key")

data = load_data()
cursor.execute("SELECT * FROM accounts WHERE username = " + data)
