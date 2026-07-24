from flask import Flask, request

app = Flask(__name__)

@app.route("/multi")
def multi():
    cursor = get_cursor()
    user = request.form.get("user")
    query = "SELECT * FROM users WHERE name = "
    query = query + user
    query = query + " AND active = 1"
    return cursor.execute(query)
