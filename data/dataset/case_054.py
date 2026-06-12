def fetch_value():
    return input("param")

val = fetch_value()
cursor.execute("SELECT * FROM products WHERE name = " + val)
