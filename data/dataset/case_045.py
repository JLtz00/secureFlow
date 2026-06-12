def read_input():
    return input("value")

name = read_input()
cursor.execute("SELECT * FROM orders WHERE email = " + name)
