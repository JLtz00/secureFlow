from flask import Flask, request

app = Flask(__name__)

@app.route("/clean/args")
def clean_args():
    raw = request.args.get("value")
    value = sanitize(raw)
    cursor.execute("SELECT * FROM sessions WHERE value = " + value)
