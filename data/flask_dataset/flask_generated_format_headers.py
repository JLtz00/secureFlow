from flask import Flask, request

app = Flask(__name__)

@app.route("/format/headers")
def format_headers():
    value = request.headers.get("X-Value")
    query = "SELECT * FROM users WHERE value = {}".format(value)
    cursor.execute(query)
