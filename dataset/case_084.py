def fetch_value():
    return input("param")

data = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + data)
