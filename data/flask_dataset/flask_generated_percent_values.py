from flask import Flask, request

app = Flask(__name__)

@app.route("/percent/values")
def percent_values():
    value = request.values.get("value")
    query = "SELECT * FROM users WHERE value = %s" % value
    cursor.execute(query)
