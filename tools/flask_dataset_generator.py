"""Generate a Flask-focused SQL injection benchmark dataset."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "data" / "flask_dataset"
DEFAULT_METADATA_FILE = PROJECT_ROOT / "data" / "flask_dataset_metadata.json"
DEFAULT_PROJECTS_DIR = PROJECT_ROOT / "data" / "flask_projects"
DEFAULT_PROJECTS_METADATA_FILE = PROJECT_ROOT / "data" / "flask_projects_metadata.json"


@dataclass
class FlaskDatasetEntry:
    file: str
    label: str
    category: str
    framework: str
    vulnerability: str
    source_line: int
    sink_line: int


class FlaskDatasetGenerator:
    def __init__(
        self,
        output_dir: str | Path = DEFAULT_DATASET_DIR,
        metadata_file: str | Path = DEFAULT_METADATA_FILE,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.metadata_file = Path(metadata_file)

    def generate(self) -> list[FlaskDatasetEntry]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        cases = [
            (
                "flask_direct_concat.py",
                "VULNERABLE",
                "direct_concat",
                8,
                9,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/users")
def users():
    cursor = get_cursor()
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = '" + user + "'")
''',
            ),
            (
                "flask_alias_form.py",
                "VULNERABLE",
                "import_alias",
                8,
                10,
                '''from flask import Flask, request as req

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    cursor = get_cursor()
    username = req.form.get("username")
    query = "SELECT * FROM users WHERE username = " + username
    cursor.execute(query)
''',
            ),
            (
                "flask_fstring.py",
                "VULNERABLE",
                "fstring",
                8,
                10,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/orders")
def orders():
    cursor = get_cursor()
    order_id = request.values.get("id")
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    cursor.execute(query)
''',
            ),
            (
                "flask_json_interprocedural.py",
                "VULNERABLE",
                "interprocedural_json",
                8,
                14,
                '''from flask import Flask, request

app = Flask(__name__)

def read_payload():
    data = request.json.get("name")
    return data

@app.route("/search", methods=["POST"])
def search():
    cursor = get_cursor()
    name = read_payload()
    query = "SELECT * FROM users WHERE name = " + name
    cursor.execute(query)
''',
            ),
            (
                "flask_dbapi_parameterized.py",
                "SAFE",
                "dbapi_parameterized",
                8,
                9,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/users")
def users():
    cursor = get_cursor()
    user = request.args.get("user")
    cursor.execute("SELECT * FROM users WHERE name = ?", (user,))
''',
            ),
            (
                "flask_sqlalchemy_text_parameterized.py",
                "SAFE",
                "sqlalchemy_text_parameterized",
                9,
                10,
                '''from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)

@app.route("/users")
def users():
    user = request.args.get("user")
    stmt = text("SELECT * FROM users WHERE name = :name")
    db.session.execute(stmt, {"name": user})
''',
            ),
            (
                "flask_sanitized.py",
                "SAFE",
                "sanitized",
                8,
                10,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/users")
def users():
    cursor = get_cursor()
    raw = request.headers.get("X-User")
    user = sanitize(raw)
    cursor.execute("SELECT * FROM users WHERE name = " + user)
''',
            ),
            (
                "flask_sqlalchemy_concat.py",
                "VULNERABLE",
                "sqlalchemy_concat",
                8,
                10,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/admin")
def admin():
    name = request.cookies.get("name")
    query = "SELECT * FROM users WHERE name = " + name
    db.session.execute(query)
''',
            ),
            (
                "flask_json_subscript.py",
                "VULNERABLE",
                "json_subscript",
                8,
                10,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/api/users", methods=["POST"])
def users():
    cursor = get_cursor()
    data = request.get_json()
    user = data["user"]
    cursor.execute("SELECT * FROM users WHERE name = " + user)
''',
            ),
            (
                "flask_json_get_format.py",
                "VULNERABLE",
                "json_get_format",
                8,
                11,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/api/search", methods=["POST"])
def search():
    cursor = get_cursor()
    data = request.get_json()
    user = data.get("user")
    query = "SELECT * FROM users WHERE name = {}".format(user)
    cursor.execute(query)
''',
            ),
            (
                "flask_percent_formatting.py",
                "VULNERABLE",
                "percent_formatting",
                8,
                10,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/legacy")
def legacy():
    cursor = get_cursor()
    user = request.args.get("user")
    query = "SELECT * FROM users WHERE name = %s" % user
    cursor.execute(query)
''',
            ),
            (
                "flask_sqlalchemy_text_dynamic.py",
                "VULNERABLE",
                "sqlalchemy_text_dynamic",
                9,
                11,
                '''from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)

@app.route("/reports")
def reports():
    user = request.args.get("user")
    raw = "SELECT * FROM users WHERE name = " + user
    stmt = text(raw)
    db.session.execute(stmt)
''',
            ),
            (
                "flask_sqlalchemy_orm_safe.py",
                "SAFE",
                "sqlalchemy_orm_safe",
                7,
                8,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/orm")
def orm_lookup():
    user = request.args.get("user")
    result = User.query.filter_by(name=user).first()
    return result
''',
            ),
            (
                "flask_blueprint_try_with.py",
                "VULNERABLE",
                "blueprint_try_with",
                10,
                13,
                '''from flask import Blueprint, request
from contextlib import closing

bp = Blueprint("users", __name__)

@bp.get("/users")
def users() -> object:
    try:
        cursor = get_cursor()
        user: str = request.args.get("user")
        with closing(cursor):
            query = "SELECT * FROM users WHERE name = " + user
            return cursor.execute(query)
    except Exception as exc:
        raise exc
''',
            ),
            (
                "flask_methodview_vulnerable.py",
                "VULNERABLE",
                "methodview_concat",
                9,
                11,
                '''from flask import request
from flask.views import MethodView

class UserView(MethodView):
    def get(self):
        cursor = get_cursor()
        user = request.args.get("user")
        query = "SELECT * FROM users WHERE name = " + user
        return cursor.execute(query)
''',
            ),
            (
                "flask_multistep_query.py",
                "VULNERABLE",
                "multistep_query",
                8,
                12,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/multi")
def multi():
    cursor = get_cursor()
    user = request.form.get("user")
    query = "SELECT * FROM users WHERE name = "
    query = query + user
    query = query + " AND active = 1"
    return cursor.execute(query)
''',
            ),
            (
                "flask_nested_json_subscript.py",
                "VULNERABLE",
                "nested_json_subscript",
                8,
                12,
                '''from flask import Flask, request

app = Flask(__name__)

@app.post("/nested")
def nested():
    cursor = get_cursor()
    payload = request.get_json()
    filters = payload.get("filters")
    user = filters["name"]
    query = "SELECT * FROM users WHERE name = " + user
    return cursor.execute(query)
''',
            ),
            (
                "flask_named_parameter_safe.py",
                "SAFE",
                "named_parameter_safe",
                8,
                9,
                '''from flask import Flask, request

app = Flask(__name__)

@app.route("/named")
def named():
    cursor = get_cursor()
    user = request.args.get("user")
    return cursor.execute("SELECT * FROM users WHERE name = :name", {"name": user})
''',
            ),
            (
                "flask_repository_parameterized_safe.py",
                "SAFE",
                "repository_parameterized_safe",
                8,
                12,
                '''from flask import Flask, request

app = Flask(__name__)

def lookup_user(cursor, value):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (value,))

@app.route("/repo-safe")
def repo_safe():
    cursor = get_cursor()
    user = request.values.get("user")
    return lookup_user(cursor, user)
''',
            ),
        ]

        self._add_generated_cases(cases)
        entries: list[FlaskDatasetEntry] = []
        for filename, label, category, source_line, sink_line, source in cases:
            (self.output_dir / filename).write_text(source)
            entries.append(
                FlaskDatasetEntry(
                    file=filename,
                    label=label,
                    category=category,
                    framework="flask",
                    vulnerability="SQLI" if label == "VULNERABLE" else "NONE",
                    source_line=source_line,
                    sink_line=sink_line,
                )
            )

        self.metadata_file.write_text(json.dumps([asdict(e) for e in entries], indent=2))
        return entries

    def _add_generated_cases(self, cases: list[tuple[str, str, str, int, int, str]]) -> None:
        sources = [
            ("args", 'request.args.get("value")'),
            ("form", 'request.form.get("value")'),
            ("values", 'request.values.get("value")'),
            ("headers", 'request.headers.get("X-Value")'),
            ("cookies", 'request.cookies.get("value")'),
            ("files", 'request.files.get("upload")'),
            ("view_args", 'request.view_args.get("value")'),
        ]
        tables = ["users", "orders", "sessions", "accounts"]
        sinks = ["cursor.execute", "db.session.execute", "connection.execute"]

        index = 1
        for source_name, source_expr in sources:
            table = tables[index % len(tables)]
            sink = sinks[index % len(sinks)]
            cases.append((
                f"flask_generated_concat_{source_name}.py",
                "VULNERABLE",
                f"generated_concat_{source_name}",
                8,
                10,
                f'''from flask import Flask, request

app = Flask(__name__)

@app.route("/generated/{source_name}")
def generated_{source_name}():
    value = {source_expr}
    query = "SELECT * FROM {table} WHERE value = " + value
    {sink}(query)
''',
            ))
            index += 1

        for source_name, source_expr in sources[:6]:
            table = tables[index % len(tables)]
            cases.append((
                f"flask_generated_parameterized_{source_name}.py",
                "SAFE",
                f"generated_parameterized_{source_name}",
                8,
                9,
                f'''from flask import Flask, request

app = Flask(__name__)

@app.route("/safe/{source_name}")
def safe_{source_name}():
    value = {source_expr}
    cursor.execute("SELECT * FROM {table} WHERE value = ?", (value,))
''',
            ))
            index += 1

        for source_name, source_expr in sources[:6]:
            table = tables[index % len(tables)]
            cases.append((
                f"flask_generated_sanitized_{source_name}.py",
                "SAFE",
                f"generated_sanitized_{source_name}",
                8,
                10,
                f'''from flask import Flask, request

app = Flask(__name__)

@app.route("/clean/{source_name}")
def clean_{source_name}():
    raw = {source_expr}
    value = sanitize(raw)
    cursor.execute("SELECT * FROM {table} WHERE value = " + value)
''',
            ))
            index += 1

        format_patterns = [
            ("format", '"SELECT * FROM users WHERE value = {}".format(value)'),
            ("percent", '"SELECT * FROM users WHERE value = %s" % value'),
            ("fstring", 'f"SELECT * FROM users WHERE value = {value}"'),
        ]
        for pattern, query_expr in format_patterns:
            for source_name, source_expr in sources[:4]:
                cases.append((
                    f"flask_generated_{pattern}_{source_name}.py",
                    "VULNERABLE",
                    f"generated_{pattern}_{source_name}",
                    8,
                    10,
                    f'''from flask import Flask, request

app = Flask(__name__)

@app.route("/{pattern}/{source_name}")
def {pattern}_{source_name}():
    value = {source_expr}
    query = {query_expr}
    cursor.execute(query)
''',
                ))

        json_cases = [
            ("json_subscript_name", 'payload["name"]'),
            ("json_get_name", 'payload.get("name")'),
            ("json_subscript_id", 'payload["id"]'),
            ("json_get_id", 'payload.get("id")'),
        ]
        for category, value_expr in json_cases:
            cases.append((
                f"flask_generated_{category}.py",
                "VULNERABLE",
                f"generated_{category}",
                8,
                11,
                f'''from flask import Flask, request

app = Flask(__name__)

@app.route("/json/{category}", methods=["POST"])
def {category}():
    payload = request.get_json()
    value = {value_expr}
    query = "SELECT * FROM users WHERE value = " + value
    cursor.execute(query)
''',
            ))

        for n in range(2):
            cases.append((
                f"flask_generated_sqlalchemy_text_safe_{n}.py",
                "SAFE",
                f"generated_sqlalchemy_text_safe_{n}",
                9,
                10,
                f'''from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)

@app.route("/text-safe-{n}")
def text_safe_{n}():
    value = request.args.get("value")
    stmt = text("SELECT * FROM users WHERE value = :value")
    db.session.execute(stmt, {{"value": value}})
''',
            ))

        for n in range(2):
            cases.append((
                f"flask_generated_sqlalchemy_text_dynamic_{n}.py",
                "VULNERABLE",
                f"generated_sqlalchemy_text_dynamic_{n}",
                9,
                11,
                f'''from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)

@app.route("/text-dynamic-{n}")
def text_dynamic_{n}():
    value = request.args.get("value")
    raw = "SELECT * FROM users WHERE value = " + value
    stmt = text(raw)
    db.session.execute(stmt)
''',
            ))


@dataclass
class FlaskProjectEntry:
    project: str
    label: str
    category: str
    framework: str
    vulnerability: str
    source_file: str
    sink_file: str
    sink_line: int


class FlaskProjectDatasetGenerator:
    def __init__(
        self,
        output_dir: str | Path = DEFAULT_PROJECTS_DIR,
        metadata_file: str | Path = DEFAULT_PROJECTS_METADATA_FILE,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.metadata_file = Path(metadata_file)

    def generate(self) -> list[FlaskProjectEntry]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        projects = [
            (
                "project_multifile_vulnerable",
                "VULNERABLE",
                "route_service_repository",
                {
                    "app.py": '''from flask import Flask
from routes import search

app = Flask(__name__)
app.add_url_rule("/search", "search", search)
''',
                    "routes.py": '''from flask import request
from services import find_user

def search():
    name = request.args.get("name")
    return find_user(name)
''',
                    "services.py": '''from repository import query_user

def find_user(name):
    return query_user(name)
''',
                    "repository.py": '''def query_user(name):
    query = "SELECT * FROM users WHERE name = " + name
    return db.session.execute(query)
''',
                },
                "routes.py",
                "repository.py",
                3,
            ),
            (
                "project_multifile_parameterized",
                "SAFE",
                "route_service_parameterized",
                {
                    "routes.py": '''from flask import request
from repository import query_user

def search():
    name = request.form.get("name")
    return query_user(name)
''',
                    "repository.py": '''def query_user(name):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
''',
                },
                "routes.py",
                "repository.py",
                2,
            ),
            (
                "project_multifile_json_format",
                "VULNERABLE",
                "json_service_format",
                {
                    "routes.py": '''from flask import request
from services import build_query

def search():
    payload = request.get_json()
    name = payload["name"]
    query = build_query(name)
    return cursor.execute(query)
''',
                    "services.py": '''def build_query(name):
    return "SELECT * FROM users WHERE name = {}".format(name)
''',
                },
                "routes.py",
                "routes.py",
                8,
            ),
            (
                "project_multifile_sanitized",
                "SAFE",
                "service_sanitized",
                {
                    "routes.py": '''from flask import request
from services import clean

def search():
    name = request.headers.get("X-User")
    safe = clean(name)
    return cursor.execute("SELECT * FROM users WHERE name = " + safe)
''',
                    "services.py": '''def clean(value):
    return sanitize(value)
''',
                },
                "routes.py",
                "routes.py",
                7,
            ),
            (
                "project_sqlite_dbapi_vulnerable",
                "VULNERABLE",
                "sqlite_repository_concat",
                {
                    "routes.py": '''from flask import request
from repository import search_users

def search():
    name = request.args.get("name")
    return search_users(name)
''',
                    "repository.py": '''import sqlite3

def search_users(name):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return cursor.execute(query)
''',
                },
                "routes.py",
                "repository.py",
                7,
            ),
            (
                "project_psycopg_parameterized",
                "SAFE",
                "psycopg_repository_parameterized",
                {
                    "routes.py": '''from flask import request
from repository import search_users

def search():
    name = request.form.get("name")
    return search_users(name)
''',
                    "repository.py": '''import psycopg

def search_users(name):
    connection = psycopg.connect("postgresql://localhost/app")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
''',
                },
                "routes.py",
                "repository.py",
                6,
            ),
            (
                "project_mysql_connector_vulnerable",
                "VULNERABLE",
                "mysql_repository_fstring",
                {
                    "routes.py": '''from flask import request
from repository import find_order

def order():
    order_id = request.values.get("id")
    return find_order(order_id)
''',
                    "repository.py": '''import mysql.connector

def find_order(order_id):
    connection = mysql.connector.connect(database="app")
    cursor = connection.cursor()
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    return cursor.execute(query)
''',
                },
                "routes.py",
                "repository.py",
                7,
            ),
            (
                "project_sqlalchemy_session_parameterized",
                "SAFE",
                "sqlalchemy_session_named_parameter",
                {
                    "routes.py": '''from flask import request
from repository import find_user

def user():
    name = request.args.get("name")
    return find_user(name)
''',
                    "repository.py": '''from sqlalchemy import text
from sqlalchemy.orm import Session

def find_user(name):
    session = Session()
    statement = text("SELECT * FROM users WHERE name = :name")
    return session.execute(statement, {"name": name})
''',
                },
                "routes.py",
                "repository.py",
                7,
            ),
        ]

        entries: list[FlaskProjectEntry] = []
        for project, label, category, files, source_file, sink_file, sink_line in projects:
            project_dir = self.output_dir / project
            project_dir.mkdir(parents=True, exist_ok=True)
            for filename, source in files.items():
                (project_dir / filename).write_text(source)
            entries.append(
                FlaskProjectEntry(
                    project=project,
                    label=label,
                    category=category,
                    framework="flask",
                    vulnerability="SQLI" if label == "VULNERABLE" else "NONE",
                    source_file=source_file,
                    sink_file=sink_file,
                    sink_line=sink_line,
                )
            )

        self.metadata_file.write_text(json.dumps([asdict(e) for e in entries], indent=2))
        return entries


def main() -> None:
    entries = FlaskDatasetGenerator().generate()
    projects = FlaskProjectDatasetGenerator().generate()
    vulnerable = sum(1 for entry in entries if entry.label == "VULNERABLE")
    safe = len(entries) - vulnerable
    print(f"Generated {len(entries)} Flask programs — {vulnerable} VULNERABLE, {safe} SAFE")
    print(f"Metadata written to {DEFAULT_METADATA_FILE}")
    project_vulnerable = sum(1 for entry in projects if entry.label == "VULNERABLE")
    project_safe = len(projects) - project_vulnerable
    print(f"Generated {len(projects)} Flask projects — {project_vulnerable} VULNERABLE, {project_safe} SAFE")
    print(f"Project metadata written to {DEFAULT_PROJECTS_METADATA_FILE}")


if __name__ == "__main__":
    main()
