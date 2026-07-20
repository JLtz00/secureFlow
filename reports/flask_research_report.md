# Flask SQL Injection Evaluation

## Dataset

- Total Flask programs: 13
- Vulnerable: 9
- Safe: 4
- Categories: dbapi_parameterized, direct_concat, fstring, import_alias, interprocedural_json, json_get_format, json_subscript, percent_formatting, sanitized, sqlalchemy_concat, sqlalchemy_orm_safe, sqlalchemy_text_dynamic, sqlalchemy_text_parameterized

## Detection Metrics

| Tool | Precision | Recall | F1 | Accuracy | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|
| SecureFlow | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Bandit | 1.000 | 0.778 | 0.875 | 0.846 | 0.000 | 0.222 |
| Semgrep | 1.000 | 0.889 | 0.941 | 0.923 | 0.000 | 0.111 |
| Pysa | 0.900 | 1.000 | 0.947 | 0.923 | 0.250 | 0.000 |

## Category-Level Results

| Category | Label | SecureFlow | Bandit | Semgrep | Pysa |
|---|---|---|---|---|---|
| direct_concat | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| import_alias | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| fstring | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| interprocedural_json | VULNERABLE | VULNERABLE | SAFE | SAFE | VULNERABLE |
| dbapi_parameterized | SAFE | SAFE | SAFE | SAFE | SAFE |
| sqlalchemy_text_parameterized | SAFE | SAFE | SAFE | SAFE | SAFE |
| sanitized | SAFE | SAFE | SAFE | SAFE | VULNERABLE |
| sqlalchemy_concat | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| json_subscript | VULNERABLE | VULNERABLE | SAFE | VULNERABLE | VULNERABLE |
| json_get_format | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| percent_formatting | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| sqlalchemy_text_dynamic | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| sqlalchemy_orm_safe | SAFE | SAFE | SAFE | SAFE | SAFE |

## Scope

This Flask profile models common request sources, DB-API and SQLAlchemy raw-query sinks, import aliases, route decorators, f-strings, percent formatting, `.format()`, JSON body extraction through subscripts and `.get()`, and parameterized query patterns.
