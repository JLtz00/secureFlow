from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)

@app.route("/text-safe-0")
def text_safe_0():
    value = request.args.get("value")
    stmt = text("SELECT * FROM users WHERE value = :value")
    db.session.execute(stmt, {"value": value})
