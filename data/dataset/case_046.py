def load_data():
    return request.form.get("key")

param = load_data()
cursor.execute("SELECT * FROM accounts WHERE username = " + param)
