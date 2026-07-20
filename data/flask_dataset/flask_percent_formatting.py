from flask import Flask, request

app = Flask(__name__)

@app.route("/legacy")
def legacy():
    cursor = get_cursor()
    user = request.args.get("user")
    query = "SELECT * FROM users WHERE name = %s" % user
    cursor.execute(query)
