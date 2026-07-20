from flask import Flask
from routes import search

app = Flask(__name__)
app.add_url_rule("/search", "search", search)
