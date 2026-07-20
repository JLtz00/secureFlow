from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)

@app.route("/text-dynamic-1")
def text_dynamic_1():
    value = request.args.get("value")
    raw = "SELECT * FROM users WHERE value = " + value
    stmt = text(raw)
    db.session.execute(stmt)
