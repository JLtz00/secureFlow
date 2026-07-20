from flask import Flask, request

app = Flask(__name__)

@app.route("/safe/cookies")
def safe_cookies():
    value = request.cookies.get("value")
    cursor.execute("SELECT * FROM users WHERE value = ?", (value,))
