from flask import Flask, request

app = Flask(__name__)

@app.route("/json/json_subscript_id", methods=["POST"])
def json_subscript_id():
    payload = request.get_json()
    value = payload["id"]
    query = "SELECT * FROM users WHERE value = " + value
    cursor.execute(query)
