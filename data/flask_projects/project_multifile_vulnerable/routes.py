from flask import request
from services import find_user

def search():
    name = request.args.get("name")
    return find_user(name)
