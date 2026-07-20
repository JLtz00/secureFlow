def build_query(name):
    return "SELECT * FROM users WHERE name = {}".format(name)
