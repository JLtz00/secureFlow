from flask import Flask, request

app = Flask(__name__)

@app.route("/orm")
def orm_lookup():
    user = request.args.get("user")
    result = User.query.filter_by(name=user).first()
    return result
