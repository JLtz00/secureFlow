from flask import Flask, request

app = Flask(__name__)

@app.route("/generated/form")
def generated_form():
    value = request.form.get("value")
    query = "SELECT * FROM sessions WHERE value = " + value
    connection.execute(query)
