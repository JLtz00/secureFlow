from flask import request
from repository import find_order

def order():
    order_id = request.values.get("id")
    return find_order(order_id)
