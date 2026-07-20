from flask import Flask, request

app = Flask(__name__)

@app.route("/users")
def users():
    cursor = get_cursor()
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = '" + user + "'")
