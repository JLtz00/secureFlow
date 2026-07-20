from flask import Flask, request

app = Flask(__name__)

@app.route("/users")
def users():
    cursor = get_cursor()
    raw = request.headers.get("X-User")
    user = sanitize(raw)
    cursor.execute("SELECT * FROM users WHERE name = " + user)
