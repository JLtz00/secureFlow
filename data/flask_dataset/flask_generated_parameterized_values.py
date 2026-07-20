from flask import Flask, request

app = Flask(__name__)

@app.route("/safe/values")
def safe_values():
    value = request.values.get("value")
    cursor.execute("SELECT * FROM sessions WHERE value = ?", (value,))
