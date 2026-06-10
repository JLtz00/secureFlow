def read_input():
    return request.args.get("value")

uid = read_input()
cursor.execute("SELECT * FROM orders WHERE email = " + uid)
