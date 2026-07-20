from flask import Flask, request

app = Flask(__name__)

@app.route("/generated/files")
def generated_files():
    value = request.files.get("upload")
    query = "SELECT * FROM sessions WHERE value = " + value
    cursor.execute(query)
