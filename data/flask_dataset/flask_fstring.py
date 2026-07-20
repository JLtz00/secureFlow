from flask import Flask, request

app = Flask(__name__)

@app.route("/orders")
def orders():
    cursor = get_cursor()
    order_id = request.values.get("id")
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    cursor.execute(query)
