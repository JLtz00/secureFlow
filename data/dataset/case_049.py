def fetch_value():
    return request.form.get("param")

data = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + data)
