from flask import Flask, request

app = Flask(__name__)

@app.route("/percent/args")
def percent_args():
    value = request.args.get("value")
    query = "SELECT * FROM users WHERE value = %s" % value
    cursor.execute(query)
