import sqlite3

def search_users(name):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return cursor.execute(query)
