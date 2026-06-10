def fetch_value():
    return request.form.get("param")

user = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + user)
