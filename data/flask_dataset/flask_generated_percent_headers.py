from flask import Flask, request

app = Flask(__name__)

@app.route("/percent/headers")
def percent_headers():
    value = request.headers.get("X-Value")
    query = "SELECT * FROM users WHERE value = %s" % value
    cursor.execute(query)
