def read_input():
    return input("value")

val = read_input()
cursor.execute("SELECT * FROM orders WHERE email = " + val)
