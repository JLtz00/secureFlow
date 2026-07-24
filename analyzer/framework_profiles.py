"""Framework-specific source, sink, sanitizer, and object models."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True)
class CallReturnModel:
    pattern: str
    returns: str


@dataclass(frozen=True)
class MethodReturnModel:
    receiver: str
    method: str
    returns: str


@dataclass(frozen=True)
class AttributeReturnModel:
    receiver: str
    attribute: str
    returns: str


@dataclass(frozen=True)
class FrameworkProfile:
    name: str
    sources: frozenset[str] = field(default_factory=frozenset)
    sinks: frozenset[str] = field(default_factory=frozenset)
    sanitizers: frozenset[str] = field(default_factory=frozenset)
    source_patterns: tuple[str, ...] = ()
    sink_patterns: tuple[str, ...] = ()
    sanitizer_patterns: tuple[str, ...] = ()
    call_returns: tuple[CallReturnModel, ...] = ()
    method_returns: tuple[MethodReturnModel, ...] = ()
    attribute_returns: tuple[AttributeReturnModel, ...] = ()
    sink_methods: tuple[tuple[str, str], ...] = ()

    def is_source(self, function: str) -> bool:
        return function in self.sources or self._matches(function, self.source_patterns)

    def is_sink(self, function: str) -> bool:
        if function in self.sinks or self._matches(function, self.sink_patterns):
            return True
        return any(
            fnmatchcase(function, f"{receiver}.{method}")
            for receiver, method in self.sink_methods
        )

    def is_sanitizer(self, function: str) -> bool:
        return function in self.sanitizers or self._matches(function, self.sanitizer_patterns)

    def call_return_kind(self, function: str) -> str | None:
        for model in self.call_returns:
            if fnmatchcase(function, model.pattern):
                return model.returns
        return None

    def method_return_kind(self, receiver_kind: str | None, method: str) -> str | None:
        if receiver_kind is None:
            return None
        for model in self.method_returns:
            if fnmatchcase(receiver_kind, model.receiver) and fnmatchcase(method, model.method):
                return model.returns
        return None

    def attribute_return_kind(self, receiver_kind: str | None, attribute: str) -> str | None:
        if receiver_kind is None:
            return None
        for model in self.attribute_returns:
            if fnmatchcase(receiver_kind, model.receiver) and fnmatchcase(attribute, model.attribute):
                return model.returns
        return None

    def canonical_call(self, function: str, receiver_kind: str | None = None) -> str:
        method = function.rsplit(".", 1)[-1]
        if receiver_kind is not None:
            for modeled_receiver, modeled_method in self.sink_methods:
                if fnmatchcase(receiver_kind, modeled_receiver) and fnmatchcase(method, modeled_method):
                    return f"{receiver_kind}.{method}"
        return function

    @staticmethod
    def _matches(value: str, patterns: tuple[str, ...]) -> bool:
        return any(fnmatchcase(value, pattern) for pattern in patterns)


BASE_PROFILE = FrameworkProfile(
    name="base",
    sources=frozenset({
        "request.args.get",
        "request.form.get",
        "input",
    }),
    sinks=frozenset({
        "cursor.execute",
        "engine.execute",
    }),
    sanitizers=frozenset({
        "escape",
        "sanitize",
    }),
)


_DATABASE_CALL_RETURNS = (
    CallReturnModel("flask.Flask", "flask.application"),
    CallReturnModel("flask.Blueprint", "flask.blueprint"),
    CallReturnModel("sqlite3.connect", "dbapi.connection"),
    CallReturnModel("psycopg.connect", "dbapi.connection"),
    CallReturnModel("psycopg2.connect", "dbapi.connection"),
    CallReturnModel("mysql.connector.connect", "dbapi.connection"),
    CallReturnModel("pymysql.connect", "dbapi.connection"),
    CallReturnModel("sqlalchemy.create_engine", "sqlalchemy.engine"),
    CallReturnModel("sqlalchemy.orm.Session", "sqlalchemy.session"),
    CallReturnModel("flask_sqlalchemy.SQLAlchemy", "flask_sqlalchemy.db"),
)

_DATABASE_METHOD_RETURNS = (
    MethodReturnModel("dbapi.connection", "cursor", "dbapi.cursor"),
    MethodReturnModel("sqlalchemy.engine", "connect", "sqlalchemy.connection"),
    MethodReturnModel("sqlalchemy.engine", "begin", "sqlalchemy.connection"),
)

_DATABASE_ATTRIBUTE_RETURNS = (
    AttributeReturnModel("flask_sqlalchemy.db", "session", "sqlalchemy.session"),
)

_DATABASE_SINK_METHODS = (
    ("dbapi.cursor", "execute"),
    ("dbapi.cursor", "executemany"),
    ("dbapi.connection", "execute"),
    ("dbapi.connection", "executemany"),
    ("sqlalchemy.engine", "execute"),
    ("sqlalchemy.connection", "execute"),
    ("sqlalchemy.session", "execute"),
)


FLASK_PROFILE = FrameworkProfile(
    name="flask",
    sources=BASE_PROFILE.sources | frozenset({
        "request.values.get",
        "request.cookies.get",
        "request.headers.get",
        "request.files.get",
        "request.view_args.get",
        "request.json.get",
        "request.get_json",
        "flask.request.args.get",
        "flask.request.form.get",
        "flask.request.values.get",
        "flask.request.cookies.get",
        "flask.request.headers.get",
        "flask.request.files.get",
        "flask.request.view_args.get",
        "flask.request.json.get",
        "flask.request.get_json",
    }),
    sinks=BASE_PROFILE.sinks | frozenset({
        "cursor.executemany",
        "connection.execute",
        "connection.executemany",
        "db.session.execute",
        "session.execute",
        "sqlalchemy.engine.execute",
        "dbapi.cursor.execute",
        "dbapi.cursor.executemany",
        "dbapi.connection.execute",
        "dbapi.connection.executemany",
        "sqlalchemy.connection.execute",
        "sqlalchemy.session.execute",
    }),
    sink_patterns=(
        "cur.execute",
        "cur.executemany",
        "conn.execute",
        "conn.executemany",
        "*cursor.execute",
        "*cursor.executemany",
        "*.connection.execute",
        "*.connection.executemany",
        "*.session.execute",
    ),
    sanitizers=BASE_PROFILE.sanitizers,
    call_returns=_DATABASE_CALL_RETURNS,
    method_returns=_DATABASE_METHOD_RETURNS,
    attribute_returns=_DATABASE_ATTRIBUTE_RETURNS,
    sink_methods=_DATABASE_SINK_METHODS,
)


PROFILES: dict[str, FrameworkProfile] = {
    BASE_PROFILE.name: BASE_PROFILE,
    FLASK_PROFILE.name: FLASK_PROFILE,
}


def get_profile(name: str = "base") -> FrameworkProfile:
    return PROFILES.get(name, BASE_PROFILE)


def load_profile(path: str | Path, base: FrameworkProfile | None = None) -> FrameworkProfile:
    """Extend a built-in profile with a project TOML model file."""
    model_path = Path(path)
    with model_path.open("rb") as handle:
        payload = tomllib.load(handle)

    profile_data = payload.get("profile", {})
    if not isinstance(profile_data, dict):
        raise ValueError("[profile] must be a TOML table")

    parent_name = str(profile_data.get("extends", "flask"))
    parent = base or get_profile(parent_name)
    return replace(
        parent,
        name=str(profile_data.get("name", f"{parent.name}+custom")),
        sources=parent.sources | _string_set(profile_data, "sources"),
        sinks=parent.sinks | _string_set(profile_data, "sinks"),
        sanitizers=parent.sanitizers | _string_set(profile_data, "sanitizers"),
        source_patterns=parent.source_patterns + _string_tuple(profile_data, "source_patterns"),
        sink_patterns=parent.sink_patterns + _string_tuple(profile_data, "sink_patterns"),
        sanitizer_patterns=parent.sanitizer_patterns + _string_tuple(
            profile_data, "sanitizer_patterns"
        ),
        call_returns=parent.call_returns + tuple(
            CallReturnModel(_required(item, "pattern"), _required(item, "returns"))
            for item in _table_list(payload, "call_returns")
        ),
        method_returns=parent.method_returns + tuple(
            MethodReturnModel(
                _required(item, "receiver"),
                _required(item, "method"),
                _required(item, "returns"),
            )
            for item in _table_list(payload, "method_returns")
        ),
        attribute_returns=parent.attribute_returns + tuple(
            AttributeReturnModel(
                _required(item, "receiver"),
                _required(item, "attribute"),
                _required(item, "returns"),
            )
            for item in _table_list(payload, "attribute_returns")
        ),
        sink_methods=parent.sink_methods + tuple(
            (_required(item, "receiver"), _required(item, "method"))
            for item in _table_list(payload, "sink_methods")
        ),
    )


def _string_set(table: dict[str, Any], key: str) -> frozenset[str]:
    return frozenset(_string_tuple(table, key))


def _string_tuple(table: dict[str, Any], key: str) -> tuple[str, ...]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be an array of strings")
    return tuple(value)


def _table_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"[[{key}]] must contain TOML tables")
    return value


def _required(table: dict[str, Any], key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing string field '{key}'")
    return value
