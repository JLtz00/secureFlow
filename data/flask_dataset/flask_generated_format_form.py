from flask import Flask, request

app = Flask(__name__)

@app.route("/format/form")
def format_form():
    value = request.form.get("value")
    query = "SELECT * FROM users WHERE value = {}".format(value)
    cursor.execute(query)
