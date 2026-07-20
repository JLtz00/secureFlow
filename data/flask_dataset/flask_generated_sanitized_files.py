from flask import Flask, request

app = Flask(__name__)

@app.route("/clean/files")
def clean_files():
    raw = request.files.get("upload")
    value = sanitize(raw)
    cursor.execute("SELECT * FROM accounts WHERE value = " + value)
