def read_input():
    return request.args.get("value")

user = read_input()
cursor.execute("SELECT * FROM orders WHERE email = " + user)
