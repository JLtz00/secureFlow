from flask import Flask, request

app = Flask(__name__)

@app.route("/format/args")
def format_args():
    value = request.args.get("value")
    query = "SELECT * FROM users WHERE value = {}".format(value)
    cursor.execute(query)
