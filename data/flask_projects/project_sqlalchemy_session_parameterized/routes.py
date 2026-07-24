from flask import request
from repository import find_user

def user():
    name = request.args.get("name")
    return find_user(name)
