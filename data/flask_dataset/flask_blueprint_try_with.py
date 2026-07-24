from flask import Blueprint, request
from contextlib import closing

bp = Blueprint("users", __name__)

@bp.get("/users")
def users() -> object:
    try:
        cursor = get_cursor()
        user: str = request.args.get("user")
        with closing(cursor):
            query = "SELECT * FROM users WHERE name = " + user
            return cursor.execute(query)
    except Exception as exc:
        raise exc
