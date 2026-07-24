"""Production-scope tests for framework models, coverage, and linking."""

from __future__ import annotations

import tempfile
from pathlib import Path

from analyzer.cfg_builder import build_cfg
from analyzer.framework_profiles import get_profile, load_profile
from analyzer.interprocedural import analyze_module
from analyzer.ir_generator import generate_ir
from analyzer.project_scanner import ProjectScanner
from analyzer.python_ast_frontend import parse_python_ast
from analyzer.taint_engine import analyze_cfg


def run_flask(source: str):
    module = generate_ir(
        parse_python_ast(source).program,
        profile=get_profile("flask"),
    )
    summaries = analyze_module(module, profile=get_profile("flask"))
    return analyze_cfg(
        build_cfg(module.main.instructions),
        summaries=summaries,
        profile=get_profile("flask"),
    )


def test_sqlite_cursor_is_resolved_as_dbapi_sink():
    result = run_flask(
        "import sqlite3\n"
        "from flask import request\n"
        "conn = sqlite3.connect(':memory:')\n"
        "cur = conn.cursor()\n"
        "name = request.args.get('name')\n"
        "cur.execute('SELECT * FROM users WHERE name = ' + name)\n"
    )
    assert result.is_vulnerable
    assert result.vulnerabilities[0].sink == "dbapi.cursor.execute"


def test_cursor_passed_as_parameter_uses_restricted_sink_pattern():
    source = (
        "def run_query(cur, query):\n"
        "    cur.execute(query)\n"
        "value = request.args.get('name')\n"
        "run_query(get_cursor(), 'SELECT * FROM users WHERE name = ' + value)\n"
    )
    module = generate_ir(
        parse_python_ast(source).program,
        profile=get_profile("flask"),
    )
    summaries = analyze_module(module, profile=get_profile("flask"))
    assert summaries["run_query"].sink_tainted_params == frozenset({1})
    result = analyze_cfg(
        build_cfg(module.main.instructions),
        summaries=summaries,
        profile=get_profile("flask"),
    )
    assert result.is_vulnerable


def test_psycopg_parameterized_query_is_safe():
    result = run_flask(
        "import psycopg\n"
        "from flask import request\n"
        "conn = psycopg.connect('postgresql://localhost/app')\n"
        "cur = conn.cursor()\n"
        "name = request.args.get('name')\n"
        "cur.execute('SELECT * FROM users WHERE name = %s', (name,))\n"
    )
    assert not result.is_vulnerable


def test_mysql_connector_nested_import_is_resolved():
    result = run_flask(
        "import mysql.connector\n"
        "from flask import request\n"
        "conn = mysql.connector.connect(database='app')\n"
        "cur = conn.cursor()\n"
        "name = request.form.get('name')\n"
        "cur.execute('SELECT * FROM users WHERE name = ' + name)\n"
    )
    assert result.is_vulnerable
    assert result.vulnerabilities[0].sink == "dbapi.cursor.execute"


def test_pymysql_named_parameter_query_is_safe():
    result = run_flask(
        "import pymysql\n"
        "from flask import request\n"
        "conn = pymysql.connect(database='app')\n"
        "cur = conn.cursor()\n"
        "name = request.form.get('name')\n"
        "cur.execute('SELECT * FROM users WHERE name = %(name)s', {'name': name})\n"
    )
    assert not result.is_vulnerable


def test_psycopg2_connection_is_modeled():
    result = run_flask(
        "import psycopg2\n"
        "from flask import request\n"
        "conn = psycopg2.connect('postgresql://localhost/app')\n"
        "cur = conn.cursor()\n"
        "name = request.args.get('name')\n"
        "cur.execute('SELECT * FROM users WHERE name = ' + name)\n"
    )
    assert result.is_vulnerable
    assert result.vulnerabilities[0].sink == "dbapi.cursor.execute"


def test_sqlalchemy_session_model_is_supported():
    result = run_flask(
        "from flask import request\n"
        "from sqlalchemy.orm import Session\n"
        "session = Session()\n"
        "name = request.args.get('name')\n"
        "session.execute('SELECT * FROM users WHERE name = ' + name)\n"
    )
    assert result.is_vulnerable
    assert result.vulnerabilities[0].sink == "sqlalchemy.session.execute"


def test_flask_sqlalchemy_session_attribute_is_modeled():
    result = run_flask(
        "from flask import request\n"
        "from flask_sqlalchemy import SQLAlchemy\n"
        "db = SQLAlchemy()\n"
        "name = request.args.get('name')\n"
        "db.session.execute('SELECT * FROM users WHERE name = ' + name)\n"
    )
    assert result.is_vulnerable
    assert result.vulnerabilities[0].sink == "sqlalchemy.session.execute"


def test_sqlalchemy_text_template_survives_interprocedural_summary():
    source = (
        "from sqlalchemy import text\n"
        "from sqlalchemy.orm import Session\n"
        "def find_user(name):\n"
        "    session = Session()\n"
        "    statement = text('SELECT * FROM users WHERE name = :name')\n"
        "    return session.execute(statement, {'name': name})\n"
        "value = request.args.get('name')\n"
        "find_user(value)\n"
    )
    module = generate_ir(
        parse_python_ast(source).program,
        profile=get_profile("flask"),
    )
    summaries = analyze_module(module, profile=get_profile("flask"))
    result = analyze_cfg(
        build_cfg(module.main.instructions),
        summaries=summaries,
        profile=get_profile("flask"),
    )
    assert not result.is_vulnerable


def test_parameterized_template_survives_cfg_block_merge():
    result = run_flask(
        "from sqlalchemy import text\n"
        "statement = text('SELECT * FROM users WHERE name = :name')\n"
        "name = request.args.get('name')\n"
        "if name:\n"
        "    audit = 'search'\n"
        "db.session.execute(statement, {'name': name})\n"
    )
    assert not result.is_vulnerable


def test_parameterized_template_survives_loop_backedge():
    result = run_flask(
        "from sqlalchemy import text\n"
        "statement = text('SELECT * FROM users WHERE name = :name')\n"
        "name = request.args.get('name')\n"
        "while pending:\n"
        "    pending = False\n"
        "db.session.execute(statement, {'name': name})\n"
    )
    assert not result.is_vulnerable


def test_access_path_assignment_reaches_sink():
    result = run_flask(
        "from flask import request\n"
        "payload = {}\n"
        "payload['name'] = request.args.get('name')\n"
        "query = 'SELECT * FROM users WHERE name = ' + payload['name']\n"
        "cursor.execute(query)\n"
    )
    assert result.is_vulnerable


def test_parameter_sensitive_summary_ignores_unrelated_tainted_argument():
    source = (
        "def run_query(query, audit_label):\n"
        "    cursor.execute(query)\n"
        "\n"
        "label = request.args.get('label')\n"
        "run_query('SELECT 1', label)\n"
    )
    module = generate_ir(
        parse_python_ast(source).program,
        profile=get_profile("flask"),
    )
    summaries = analyze_module(module, profile=get_profile("flask"))
    assert summaries["run_query"].sink_tainted_params == frozenset({0})
    result = analyze_cfg(
        build_cfg(module.main.instructions),
        summaries=summaries,
        profile=get_profile("flask"),
    )
    assert not result.is_vulnerable


def test_parameter_sensitive_summary_detects_relevant_argument():
    source = (
        "def run_query(query, audit_label):\n"
        "    cursor.execute(query)\n"
        "\n"
        "query = request.args.get('query')\n"
        "run_query(query, 'search')\n"
    )
    module = generate_ir(
        parse_python_ast(source).program,
        profile=get_profile("flask"),
    )
    summaries = analyze_module(module, profile=get_profile("flask"))
    result = analyze_cfg(
        build_cfg(module.main.instructions),
        summaries=summaries,
        profile=get_profile("flask"),
    )
    assert result.is_vulnerable


def test_frontend_approximates_comprehension_without_losing_coverage():
    result = parse_python_ast("values = [item for item in source]\n")
    assert result.coverage.ignored_nodes == 0
    assert result.coverage.approximated_nodes == 1
    assert result.coverage.coverage_ratio == 1.0
    assert result.coverage.issues[0].node == "ListComp"


def test_scanner_marks_partial_file_instead_of_ok():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "app.py"
        path.write_text(
            "match value:\n"
            "    case 1:\n"
            "        result = 'one'\n",
            encoding="utf-8",
        )
        result = ProjectScanner(tmp).scan()
        assert result.files_partial == 1
        assert result.files[0].status == "PARTIAL"
        assert result.nodes_ignored == 1


def test_frontend_conservatively_lowers_common_real_python_expressions():
    result = parse_python_ast(
        "transform = lambda value: value.strip()\n"
        "selected = value if enabled else fallback\n"
        "items = [item for item in source if item]\n"
        "stream = (item for item in items)\n"
        "mapping = {item: item for item in items}\n"
        "window = items[1:limit]\n"
        "consume(*items)\n"
        "\n"
        "def generate(values):\n"
        "    for value in values:\n"
        "        if not value:\n"
        "            continue\n"
        "        yield value\n"
    )

    assert result.coverage.ignored_nodes == 0
    approximated = {issue.node for issue in result.coverage.issues}
    assert {
        "Lambda",
        "IfExp",
        "ListComp",
        "GeneratorExp",
        "DictComp",
        "Slice",
        "Starred",
        "Continue",
        "Yield",
    } <= approximated


def test_frontend_treats_pass_as_supported_noop():
    result = parse_python_ast(
        "class Repository:\n"
        "    def save(self, value):\n"
        "        pass\n"
    )

    assert result.coverage.ignored_nodes == 0
    assert result.coverage.coverage_ratio == 1.0
    assert result.program.body


def test_if_expression_preserves_taint_on_either_branch():
    result = run_flask(
        "from flask import request\n"
        "name = request.args.get('name')\n"
        "query = ('SELECT 1' if safe else 'SELECT * FROM users WHERE name=' + name)\n"
        "cursor.execute(query)\n"
    )

    assert result.is_vulnerable


def test_project_linker_resolves_relative_imports_and_duplicate_names():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "pkg").mkdir()
        (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (root / "pkg" / "repository.py").write_text(
            "def execute_query(value):\n"
            "    cursor.execute('SELECT * FROM users WHERE name = ' + value)\n",
            encoding="utf-8",
        )
        (root / "pkg" / "safe.py").write_text(
            "def execute_query(value):\n"
            "    return value\n",
            encoding="utf-8",
        )
        (root / "pkg" / "routes.py").write_text(
            "from flask import request\n"
            "from .repository import execute_query\n"
            "def search():\n"
            "    value = request.args.get('name')\n"
            "    return execute_query(value)\n",
            encoding="utf-8",
        )
        result = ProjectScanner(root).scan()
        assert len(result.findings) == 1


def test_project_linker_resolves_bound_method_export_alias():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repository.py").write_text(
            "class UserRepository:\n"
            "    def find(self, name):\n"
            "        cursor.execute('SELECT * FROM users WHERE name = ' + name)\n"
            "\n"
            "repository = UserRepository()\n"
            "find_user = repository.find\n",
            encoding="utf-8",
        )
        (root / "routes.py").write_text(
            "from flask import request\n"
            "from repository import find_user\n"
            "\n"
            "def search():\n"
            "    name = request.args.get('name')\n"
            "    return find_user(name)\n",
            encoding="utf-8",
        )

        result = ProjectScanner(root).scan()

        assert len(result.findings) == 1
        assert result.findings[0].function == "UserRepository.find"
        assert result.unresolved_calls == 0


def test_project_linker_follows_constructor_injected_layered_services():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repository.py").write_text(
            "class UserRepository:\n"
            "    def find(self, name):\n"
            "        cursor.execute('SELECT * FROM users WHERE name = ' + name)\n",
            encoding="utf-8",
        )
        (root / "service.py").write_text(
            "class UserService:\n"
            "    def __init__(self, repository):\n"
            "        self.repository = repository\n"
            "\n"
            "    def find(self, name):\n"
            "        return self.repository.find(name)\n",
            encoding="utf-8",
        )
        (root / "controller.py").write_text(
            "class UserController:\n"
            "    def __init__(self, service):\n"
            "        self.service = service\n"
            "\n"
            "    def search(self, name):\n"
            "        return self.service.find(name)\n",
            encoding="utf-8",
        )
        (root / "routes.py").write_text(
            "from flask import request\n"
            "from repository import UserRepository\n"
            "from service import UserService\n"
            "from controller import UserController\n"
            "\n"
            "def build_controller():\n"
            "    repository = UserRepository()\n"
            "    service = UserService(repository)\n"
            "    return UserController(service)\n"
            "\n"
            "def search():\n"
            "    name = request.args.get('name')\n"
            "    controller = build_controller()\n"
            "    return controller.search(name)\n",
            encoding="utf-8",
        )

        result = ProjectScanner(root).scan()

        assert len(result.findings) == 1
        assert result.findings[0].file == "repository.py"
        assert result.findings[0].function == "UserRepository.find"
        assert result.unresolved_calls == 0


def test_scanner_separates_external_calls_from_unlinked_project_calls():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(
            "def configure(app):\n"
            "    app.logger.info('ready')\n"
            "    missing_project_call()\n",
            encoding="utf-8",
        )

        result = ProjectScanner(root).scan()

        assert result.unresolved_calls == 1
        assert result.files[0].unresolved_calls == ["missing_project_call"]
        assert result.conservative_calls == 1
        assert result.files[0].conservative_calls == ["app.logger.info"]


def test_scanner_classifies_collection_and_orm_calls_as_external_conservative():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(
            "def save(self, model):\n"
            "    self.items.append(model)\n"
            "    db.session.add(model)\n"
            "    return UserModel.query.filter_by(id=model.id).first()\n",
            encoding="utf-8",
        )

        result = ProjectScanner(root).scan()

        assert result.unresolved_calls == 0
        assert result.conservative_calls == 3


def test_scanner_can_exclude_test_directory():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (root / "tests").mkdir()
        (root / "tests" / "test_app.py").write_text(
            "client.get('/')\n",
            encoding="utf-8",
        )
        excludes = set(ProjectScanner.DEFAULT_EXCLUDE_DIRS) | {"tests"}

        result = ProjectScanner(root, exclude_dirs=excludes).scan()

        assert result.files_total == 1
        assert result.files[0].path == "app.py"


def test_custom_toml_profile_extends_sources_and_database_models():
    with tempfile.TemporaryDirectory() as tmp:
        model_path = Path(tmp) / "models.toml"
        model_path.write_text(
            "[profile]\n"
            "name = 'custom'\n"
            "extends = 'flask'\n"
            "sources = ['company.request.value']\n"
            "\n"
            "[[call_returns]]\n"
            "pattern = 'company.db.connect'\n"
            "returns = 'company.connection'\n"
            "\n"
            "[[sink_methods]]\n"
            "receiver = 'company.connection'\n"
            "method = 'execute'\n",
            encoding="utf-8",
        )
        profile = load_profile(model_path)
        module = generate_ir(
            parse_python_ast(
                "from company import request\n"
                "from company import db\n"
                "conn = db.connect()\n"
                "value = request.value()\n"
                "conn.execute(value)\n"
            ).program,
            profile=profile,
        )
        result = analyze_cfg(
            build_cfg(module.main.instructions),
            profile=profile,
        )
        assert result.is_vulnerable
        assert result.vulnerabilities[0].sink == "company.connection.execute"
