import mysql.connector

def find_order(order_id):
    connection = mysql.connector.connect(database="app")
    cursor = connection.cursor()
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    return cursor.execute(query)
