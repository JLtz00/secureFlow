from flask import Flask, request

app = Flask(__name__)

@app.route("/clean/values")
def clean_values():
    raw = request.values.get("value")
    value = sanitize(raw)
    cursor.execute("SELECT * FROM users WHERE value = " + value)
