from flask import Flask, request

app = Flask(__name__)

def lookup_user(cursor, value):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (value,))

@app.route("/repo-safe")
def repo_safe():
    cursor = get_cursor()
    user = request.values.get("user")
    return lookup_user(cursor, user)
