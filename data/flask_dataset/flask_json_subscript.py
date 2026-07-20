from flask import Flask, request

app = Flask(__name__)

@app.route("/api/users", methods=["POST"])
def users():
    cursor = get_cursor()
    data = request.get_json()
    user = data["user"]
    cursor.execute("SELECT * FROM users WHERE name = " + user)
