from flask import Flask, request

app = Flask(__name__)

@app.route("/clean/cookies")
def clean_cookies():
    raw = request.cookies.get("value")
    value = sanitize(raw)
    cursor.execute("SELECT * FROM sessions WHERE value = " + value)
