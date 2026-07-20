from flask import Flask, request

app = Flask(__name__)

@app.route("/json/json_subscript_name", methods=["POST"])
def json_subscript_name():
    payload = request.get_json()
    value = payload["name"]
    query = "SELECT * FROM users WHERE value = " + value
    cursor.execute(query)
