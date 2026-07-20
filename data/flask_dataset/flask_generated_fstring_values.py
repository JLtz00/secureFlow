from flask import Flask, request

app = Flask(__name__)

@app.route("/fstring/values")
def fstring_values():
    value = request.values.get("value")
    query = f"SELECT * FROM users WHERE value = {value}"
    cursor.execute(query)
