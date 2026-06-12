def load_data():
    return request.form.get("key")

entry = load_data()
cursor.execute("SELECT * FROM accounts WHERE username = " + entry)
