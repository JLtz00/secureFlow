from flask import Flask, request

app = Flask(__name__)

@app.route("/generated/args")
def generated_args():
    value = request.args.get("value")
    query = "SELECT * FROM orders WHERE value = " + value
    db.session.execute(query)
