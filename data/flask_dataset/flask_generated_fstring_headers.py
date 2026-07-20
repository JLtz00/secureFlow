from flask import Flask, request

app = Flask(__name__)

@app.route("/fstring/headers")
def fstring_headers():
    value = request.headers.get("X-Value")
    query = f"SELECT * FROM users WHERE value = {value}"
    cursor.execute(query)
