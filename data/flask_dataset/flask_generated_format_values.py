from flask import Flask, request

app = Flask(__name__)

@app.route("/format/values")
def format_values():
    value = request.values.get("value")
    query = "SELECT * FROM users WHERE value = {}".format(value)
    cursor.execute(query)
