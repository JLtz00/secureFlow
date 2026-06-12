def load_data():
    return request.form.get("key")

val = load_data()
cursor.execute("SELECT * FROM accounts WHERE username = " + val)
