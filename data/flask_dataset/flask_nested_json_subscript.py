from flask import Flask, request

app = Flask(__name__)

@app.post("/nested")
def nested():
    cursor = get_cursor()
    payload = request.get_json()
    filters = payload.get("filters")
    user = filters["name"]
    query = "SELECT * FROM users WHERE name = " + user
    return cursor.execute(query)
