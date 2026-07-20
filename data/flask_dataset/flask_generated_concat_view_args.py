from flask import Flask, request

app = Flask(__name__)

@app.route("/generated/view_args")
def generated_view_args():
    value = request.view_args.get("value")
    query = "SELECT * FROM accounts WHERE value = " + value
    db.session.execute(query)
