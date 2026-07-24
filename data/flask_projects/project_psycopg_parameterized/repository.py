import psycopg

def search_users(name):
    connection = psycopg.connect("postgresql://localhost/app")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
