from flask import Flask, request

app = Flask(__name__)

@app.route("/safe/files")
def safe_files():
    value = request.files.get("upload")
    cursor.execute("SELECT * FROM orders WHERE value = ?", (value,))
