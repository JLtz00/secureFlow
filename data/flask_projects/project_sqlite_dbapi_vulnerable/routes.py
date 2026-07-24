from flask import request
from repository import search_users

def search():
    name = request.args.get("name")
    return search_users(name)
