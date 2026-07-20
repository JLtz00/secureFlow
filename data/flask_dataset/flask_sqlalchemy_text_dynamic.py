from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)

@app.route("/reports")
def reports():
    user = request.args.get("user")
    raw = "SELECT * FROM users WHERE name = " + user
    stmt = text(raw)
    db.session.execute(stmt)
