from flask import Flask, request

app = Flask(__name__)

@app.route("/clean/headers")
def clean_headers():
    raw = request.headers.get("X-Value")
    value = sanitize(raw)
    cursor.execute("SELECT * FROM orders WHERE value = " + value)
