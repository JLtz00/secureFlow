from flask import request
from services import clean

def search():
    name = request.headers.get("X-User")
    safe = clean(name)
    return cursor.execute("SELECT * FROM users WHERE name = " + safe)
