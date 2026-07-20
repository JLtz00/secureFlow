from flask import Flask, request

app = Flask(__name__)

@app.route("/json/json_get_name", methods=["POST"])
def json_get_name():
    payload = request.get_json()
    value = payload.get("name")
    query = "SELECT * FROM users WHERE value = " + value
    cursor.execute(query)
