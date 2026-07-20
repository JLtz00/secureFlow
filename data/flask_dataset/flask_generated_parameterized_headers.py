from flask import Flask, request

app = Flask(__name__)

@app.route("/safe/headers")
def safe_headers():
    value = request.headers.get("X-Value")
    cursor.execute("SELECT * FROM accounts WHERE value = ?", (value,))
