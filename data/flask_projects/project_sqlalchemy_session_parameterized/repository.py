from sqlalchemy import text
from sqlalchemy.orm import Session

def find_user(name):
    session = Session()
    statement = text("SELECT * FROM users WHERE name = :name")
    return session.execute(statement, {"name": name})
