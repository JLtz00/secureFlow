def read_input():
    return request.form.get("value")

entry = read_input()
cursor.execute("SELECT * FROM orders WHERE email = " + entry)
