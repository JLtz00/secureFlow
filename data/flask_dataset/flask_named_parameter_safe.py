from flask import Flask, request

app = Flask(__name__)

@app.route("/named")
def named():
    cursor = get_cursor()
    user = request.args.get("user")
    return cursor.execute("SELECT * FROM users WHERE name = :name", {"name": user})
