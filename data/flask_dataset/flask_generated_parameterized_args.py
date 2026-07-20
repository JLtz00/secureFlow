from flask import Flask, request

app = Flask(__name__)

@app.route("/safe/args")
def safe_args():
    value = request.args.get("value")
    cursor.execute("SELECT * FROM users WHERE value = ?", (value,))
