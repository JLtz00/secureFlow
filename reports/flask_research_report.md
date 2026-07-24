# SecureFlow Flask Internal Validation

## Dataset

- Total Flask programs: 58
- Vulnerable: 38
- Safe: 20
- Categories: blueprint_try_with, dbapi_parameterized, direct_concat, fstring, generated_concat_args, generated_concat_cookies, generated_concat_files, generated_concat_form, generated_concat_headers, generated_concat_values, generated_concat_view_args, generated_format_args, generated_format_form, generated_format_headers, generated_format_values, generated_fstring_args, generated_fstring_form, generated_fstring_headers, generated_fstring_values, generated_json_get_id, generated_json_get_name, generated_json_subscript_id, generated_json_subscript_name, generated_parameterized_args, generated_parameterized_cookies, generated_parameterized_files, generated_parameterized_form, generated_parameterized_headers, generated_parameterized_values, generated_percent_args, generated_percent_form, generated_percent_headers, generated_percent_values, generated_sanitized_args, generated_sanitized_cookies, generated_sanitized_files, generated_sanitized_form, generated_sanitized_headers, generated_sanitized_values, generated_sqlalchemy_text_dynamic_0, generated_sqlalchemy_text_dynamic_1, generated_sqlalchemy_text_safe_0, generated_sqlalchemy_text_safe_1, import_alias, interprocedural_json, json_get_format, json_subscript, methodview_concat, multistep_query, named_parameter_safe, nested_json_subscript, percent_formatting, repository_parameterized_safe, sanitized, sqlalchemy_concat, sqlalchemy_orm_safe, sqlalchemy_text_dynamic, sqlalchemy_text_parameterized

## Detection Metrics

Bootstrap intervals use 1,000 resamples with fixed seed 42.

| Tool | Precision 95% CI | Recall 95% CI | F1 95% CI | Accuracy 95% CI | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|
| SecureFlow | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 | 0.000 |

## Category-Level Results

| Category | Label | SecureFlow |
|---|---|---|
| direct_concat | VULNERABLE | VULNERABLE |
| import_alias | VULNERABLE | VULNERABLE |
| fstring | VULNERABLE | VULNERABLE |
| interprocedural_json | VULNERABLE | VULNERABLE |
| dbapi_parameterized | SAFE | SAFE |
| sqlalchemy_text_parameterized | SAFE | SAFE |
| sanitized | SAFE | SAFE |
| sqlalchemy_concat | VULNERABLE | VULNERABLE |
| json_subscript | VULNERABLE | VULNERABLE |
| json_get_format | VULNERABLE | VULNERABLE |
| percent_formatting | VULNERABLE | VULNERABLE |
| sqlalchemy_text_dynamic | VULNERABLE | VULNERABLE |
| sqlalchemy_orm_safe | SAFE | SAFE |
| blueprint_try_with | VULNERABLE | VULNERABLE |
| methodview_concat | VULNERABLE | VULNERABLE |
| multistep_query | VULNERABLE | VULNERABLE |
| nested_json_subscript | VULNERABLE | VULNERABLE |
| named_parameter_safe | SAFE | SAFE |
| repository_parameterized_safe | SAFE | SAFE |
| generated_concat_args | VULNERABLE | VULNERABLE |
| generated_concat_form | VULNERABLE | VULNERABLE |
| generated_concat_values | VULNERABLE | VULNERABLE |
| generated_concat_headers | VULNERABLE | VULNERABLE |
| generated_concat_cookies | VULNERABLE | VULNERABLE |
| generated_concat_files | VULNERABLE | VULNERABLE |
| generated_concat_view_args | VULNERABLE | VULNERABLE |
| generated_parameterized_args | SAFE | SAFE |
| generated_parameterized_form | SAFE | SAFE |
| generated_parameterized_values | SAFE | SAFE |
| generated_parameterized_headers | SAFE | SAFE |
| generated_parameterized_cookies | SAFE | SAFE |
| generated_parameterized_files | SAFE | SAFE |
| generated_sanitized_args | SAFE | SAFE |
| generated_sanitized_form | SAFE | SAFE |
| generated_sanitized_values | SAFE | SAFE |
| generated_sanitized_headers | SAFE | SAFE |
| generated_sanitized_cookies | SAFE | SAFE |
| generated_sanitized_files | SAFE | SAFE |
| generated_format_args | VULNERABLE | VULNERABLE |
| generated_format_form | VULNERABLE | VULNERABLE |
| generated_format_values | VULNERABLE | VULNERABLE |
| generated_format_headers | VULNERABLE | VULNERABLE |
| generated_percent_args | VULNERABLE | VULNERABLE |
| generated_percent_form | VULNERABLE | VULNERABLE |
| generated_percent_values | VULNERABLE | VULNERABLE |
| generated_percent_headers | VULNERABLE | VULNERABLE |
| generated_fstring_args | VULNERABLE | VULNERABLE |
| generated_fstring_form | VULNERABLE | VULNERABLE |
| generated_fstring_values | VULNERABLE | VULNERABLE |
| generated_fstring_headers | VULNERABLE | VULNERABLE |
| generated_json_subscript_name | VULNERABLE | VULNERABLE |
| generated_json_get_name | VULNERABLE | VULNERABLE |
| generated_json_subscript_id | VULNERABLE | VULNERABLE |
| generated_json_get_id | VULNERABLE | VULNERABLE |
| generated_sqlalchemy_text_safe_0 | SAFE | SAFE |
| generated_sqlalchemy_text_safe_1 | SAFE | SAFE |
| generated_sqlalchemy_text_dynamic_0 | VULNERABLE | VULNERABLE |
| generated_sqlalchemy_text_dynamic_1 | VULNERABLE | VULNERABLE |

## Multi-File Flask Projects

- Projects: 8
- Correct project-level classifications: 8/8

| Project | Category | Label | Prediction | Files | Partial | Coverage | Internal unlinked | External conservative | Findings |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| project_multifile_vulnerable | route_service_repository | VULNERABLE | VULNERABLE | 4 | 0 | 100.0% | 0 | 1 | 1 |
| project_multifile_parameterized | route_service_parameterized | SAFE | SAFE | 2 | 0 | 100.0% | 0 | 0 | 0 |
| project_multifile_json_format | json_service_format | VULNERABLE | VULNERABLE | 2 | 0 | 100.0% | 0 | 1 | 1 |
| project_multifile_sanitized | service_sanitized | SAFE | SAFE | 2 | 0 | 100.0% | 0 | 0 | 0 |
| project_sqlite_dbapi_vulnerable | sqlite_repository_concat | VULNERABLE | VULNERABLE | 2 | 0 | 100.0% | 0 | 0 | 1 |
| project_psycopg_parameterized | psycopg_repository_parameterized | SAFE | SAFE | 2 | 0 | 100.0% | 0 | 0 | 0 |
| project_mysql_connector_vulnerable | mysql_repository_fstring | VULNERABLE | VULNERABLE | 2 | 0 | 100.0% | 0 | 0 | 1 |
| project_sqlalchemy_session_parameterized | sqlalchemy_session_named_parameter | SAFE | SAFE | 2 | 0 | 100.0% | 0 | 0 | 0 |


## Scope

This Flask profile models common request sources, DB-API drivers, SQLite, PostgreSQL, MySQL, SQLAlchemy raw-query sinks, import aliases, route decorators, f-strings, percent formatting, `.format()`, access paths, JSON extraction and parameterized query patterns. Ignored nodes, unlinked internal calls and external APIs handled with conservative taint propagation are reported separately.

This report contains SecureFlow internal-validation results only. Empirical
comparisons with real Bandit and Semgrep executions are reported in
`reports/final/presentation_report.md`.
