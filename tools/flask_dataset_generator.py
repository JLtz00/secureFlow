"""Generate a Flask-focused SQL injection benchmark dataset."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "data" / "flask_dataset"
DEFAULT_METADATA_FILE = PROJECT_ROOT / "data" / "flask_dataset_metadata.json"


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
        ]

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


def main() -> None:
    entries = FlaskDatasetGenerator().generate()
    vulnerable = sum(1 for entry in entries if entry.label == "VULNERABLE")
    safe = len(entries) - vulnerable
    print(f"Generated {len(entries)} Flask programs — {vulnerable} VULNERABLE, {safe} SAFE")
    print(f"Metadata written to {DEFAULT_METADATA_FILE}")


if __name__ == "__main__":
    main()

