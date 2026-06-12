def fetch_value():
    return request.args.get("param")

uid = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + uid)
