from flask import Flask, request

app = Flask(__name__)

@app.route("/api/search", methods=["POST"])
def search():
    cursor = get_cursor()
    data = request.get_json()
    user = data.get("user")
    query = "SELECT * FROM users WHERE name = {}".format(user)
    cursor.execute(query)
