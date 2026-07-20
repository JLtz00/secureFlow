from flask import Flask, request

app = Flask(__name__)

def read_payload():
    data = request.json.get("name")
    return data

@app.route("/search", methods=["POST"])
def search():
    cursor = get_cursor()
    name = read_payload()
    query = "SELECT * FROM users WHERE name = " + name
    cursor.execute(query)
