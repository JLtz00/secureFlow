from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)

@app.route("/users")
def users():
    user = request.args.get("user")
    stmt = text("SELECT * FROM users WHERE name = :name")
    db.session.execute(stmt, {"name": user})
