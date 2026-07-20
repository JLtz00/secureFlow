from flask import Flask, request

app = Flask(__name__)

@app.route("/fstring/form")
def fstring_form():
    value = request.form.get("value")
    query = f"SELECT * FROM users WHERE value = {value}"
    cursor.execute(query)
