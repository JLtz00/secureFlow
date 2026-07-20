from flask import Flask, request

app = Flask(__name__)

@app.route("/safe/form")
def safe_form():
    value = request.form.get("value")
    cursor.execute("SELECT * FROM orders WHERE value = ?", (value,))
