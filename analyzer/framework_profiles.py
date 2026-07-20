"""Framework-specific source, sink, and sanitizer profiles."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FrameworkProfile:
    name: str
    sources: frozenset[str] = field(default_factory=frozenset)
    sinks: frozenset[str] = field(default_factory=frozenset)
    sanitizers: frozenset[str] = field(default_factory=frozenset)


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
    }),
    sanitizers=BASE_PROFILE.sanitizers,
)


PROFILES: dict[str, FrameworkProfile] = {
    BASE_PROFILE.name: BASE_PROFILE,
    FLASK_PROFILE.name: FLASK_PROFILE,
}


def get_profile(name: str = "base") -> FrameworkProfile:
    return PROFILES.get(name, BASE_PROFILE)
