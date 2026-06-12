def fetch_value():
    return request.args.get("param")

param = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + param)
