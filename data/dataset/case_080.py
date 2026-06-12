def read_input():
    return request.args.get("value")

name = read_input()
cursor.execute("SELECT * FROM orders WHERE email = " + name)
