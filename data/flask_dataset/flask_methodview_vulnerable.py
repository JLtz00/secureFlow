from flask import request
from flask.views import MethodView

class UserView(MethodView):
    def get(self):
        cursor = get_cursor()
        user = request.args.get("user")
        query = "SELECT * FROM users WHERE name = " + user
        return cursor.execute(query)
