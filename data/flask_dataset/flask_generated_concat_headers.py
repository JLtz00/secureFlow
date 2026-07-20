from flask import Flask, request

app = Flask(__name__)

@app.route("/generated/headers")
def generated_headers():
    value = request.headers.get("X-Value")
    query = "SELECT * FROM users WHERE value = " + value
    db.session.execute(query)
