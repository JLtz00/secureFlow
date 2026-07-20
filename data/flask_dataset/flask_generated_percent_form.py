from flask import Flask, request

app = Flask(__name__)

@app.route("/percent/form")
def percent_form():
    value = request.form.get("value")
    query = "SELECT * FROM users WHERE value = %s" % value
    cursor.execute(query)
