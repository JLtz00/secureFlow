from flask import Flask, request

app = Flask(__name__)

@app.route("/json/json_get_id", methods=["POST"])
def json_get_id():
    payload = request.get_json()
    value = payload.get("id")
    query = "SELECT * FROM users WHERE value = " + value
    cursor.execute(query)
