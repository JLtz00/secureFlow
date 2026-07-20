from flask import request
from repository import query_user

def search():
    name = request.form.get("name")
    return query_user(name)
