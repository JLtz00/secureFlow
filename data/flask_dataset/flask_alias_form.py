from flask import Flask, request as req

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    cursor = get_cursor()
    username = req.form.get("username")
    query = "SELECT * FROM users WHERE username = " + username
    cursor.execute(query)
