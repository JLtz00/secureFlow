from flask import Flask, request

app = Flask(__name__)

@app.route("/clean/form")
def clean_form():
    raw = request.form.get("value")
    value = sanitize(raw)
    cursor.execute("SELECT * FROM accounts WHERE value = " + value)
