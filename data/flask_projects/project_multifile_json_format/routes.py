from flask import request
from services import build_query

def search():
    payload = request.get_json()
    name = payload["name"]
    query = build_query(name)
    return cursor.execute(query)
