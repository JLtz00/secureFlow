def read_input():
    return request.form.get("value")

data = read_input()
cursor.execute("SELECT * FROM orders WHERE email = " + data)
