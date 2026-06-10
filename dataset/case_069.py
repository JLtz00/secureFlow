def fetch_value():
    return input("param")

entry = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + entry)
