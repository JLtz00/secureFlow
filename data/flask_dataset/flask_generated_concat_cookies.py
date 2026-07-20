from flask import Flask, request

app = Flask(__name__)

@app.route("/generated/cookies")
def generated_cookies():
    value = request.cookies.get("value")
    query = "SELECT * FROM orders WHERE value = " + value
    connection.execute(query)
