from flask import Flask, request

app = Flask(__name__)

@app.route("/admin")
def admin():
    name = request.cookies.get("name")
    query = "SELECT * FROM users WHERE name = " + name
    db.session.execute(query)
