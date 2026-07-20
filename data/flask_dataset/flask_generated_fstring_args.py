from flask import Flask, request

app = Flask(__name__)

@app.route("/fstring/args")
def fstring_args():
    value = request.args.get("value")
    query = f"SELECT * FROM users WHERE value = {value}"
    cursor.execute(query)
