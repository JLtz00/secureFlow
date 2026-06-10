def fetch_value():
    return request.form.get("param")

uid = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + uid)
