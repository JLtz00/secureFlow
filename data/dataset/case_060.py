def read_input():
    return input("value")

param = read_input()
cursor.execute("SELECT * FROM orders WHERE email = " + param)
