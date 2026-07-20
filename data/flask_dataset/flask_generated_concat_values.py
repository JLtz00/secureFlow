from flask import Flask, request

app = Flask(__name__)

@app.route("/generated/values")
def generated_values():
    value = request.values.get("value")
    query = "SELECT * FROM accounts WHERE value = " + value
    cursor.execute(query)
