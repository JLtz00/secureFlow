def fetch_value():
    return request.args.get("param")

name = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + name)
