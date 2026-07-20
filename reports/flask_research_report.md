# Flask SQL Injection Evaluation

## Dataset

- Total Flask programs: 52
- Vulnerable: 34
- Safe: 18
- Categories: dbapi_parameterized, direct_concat, fstring, generated_concat_args, generated_concat_cookies, generated_concat_files, generated_concat_form, generated_concat_headers, generated_concat_values, generated_concat_view_args, generated_format_args, generated_format_form, generated_format_headers, generated_format_values, generated_fstring_args, generated_fstring_form, generated_fstring_headers, generated_fstring_values, generated_json_get_id, generated_json_get_name, generated_json_subscript_id, generated_json_subscript_name, generated_parameterized_args, generated_parameterized_cookies, generated_parameterized_files, generated_parameterized_form, generated_parameterized_headers, generated_parameterized_values, generated_percent_args, generated_percent_form, generated_percent_headers, generated_percent_values, generated_sanitized_args, generated_sanitized_cookies, generated_sanitized_files, generated_sanitized_form, generated_sanitized_headers, generated_sanitized_values, generated_sqlalchemy_text_dynamic_0, generated_sqlalchemy_text_dynamic_1, generated_sqlalchemy_text_safe_0, generated_sqlalchemy_text_safe_1, import_alias, interprocedural_json, json_get_format, json_subscript, percent_formatting, sanitized, sqlalchemy_concat, sqlalchemy_orm_safe, sqlalchemy_text_dynamic, sqlalchemy_text_parameterized

## Detection Metrics

Bootstrap intervals use 1,000 resamples with fixed seed 42.

| Tool | Precision 95% CI | Recall 95% CI | F1 95% CI | Accuracy 95% CI | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|
| SecureFlow | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 | 0.000 |
| Bandit | 0.941 [0.848, 1.000] | 0.941 [0.846, 1.000] | 0.941 [0.881, 0.987] | 0.923 [0.846, 0.981] | 0.111 | 0.059 |
| Semgrep | 0.943 [0.853, 1.000] | 0.971 [0.900, 1.000] | 0.957 [0.901, 1.000] | 0.942 [0.865, 1.000] | 0.111 | 0.029 |
| Pysa | 0.829 [0.703, 0.932] | 1.000 [1.000, 1.000] | 0.907 [0.831, 0.967] | 0.865 [0.769, 0.942] | 0.389 | 0.000 |

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
| generated_concat_args | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_concat_form | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_concat_values | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_concat_headers | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_concat_cookies | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_concat_files | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_concat_view_args | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_parameterized_args | SAFE | SAFE | SAFE | SAFE | SAFE |
| generated_parameterized_form | SAFE | SAFE | SAFE | SAFE | SAFE |
| generated_parameterized_values | SAFE | SAFE | SAFE | SAFE | SAFE |
| generated_parameterized_headers | SAFE | SAFE | SAFE | SAFE | SAFE |
| generated_parameterized_cookies | SAFE | SAFE | SAFE | SAFE | SAFE |
| generated_parameterized_files | SAFE | SAFE | SAFE | SAFE | SAFE |
| generated_sanitized_args | SAFE | SAFE | SAFE | SAFE | VULNERABLE |
| generated_sanitized_form | SAFE | SAFE | SAFE | SAFE | VULNERABLE |
| generated_sanitized_values | SAFE | SAFE | SAFE | SAFE | VULNERABLE |
| generated_sanitized_headers | SAFE | SAFE | SAFE | SAFE | VULNERABLE |
| generated_sanitized_cookies | SAFE | SAFE | SAFE | SAFE | VULNERABLE |
| generated_sanitized_files | SAFE | SAFE | SAFE | SAFE | VULNERABLE |
| generated_format_args | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_format_form | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_format_values | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_format_headers | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_percent_args | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_percent_form | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_percent_values | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_percent_headers | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_fstring_args | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_fstring_form | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_fstring_values | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_fstring_headers | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_json_subscript_name | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_json_get_name | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_json_subscript_id | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_json_get_id | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_sqlalchemy_text_safe_0 | SAFE | SAFE | VULNERABLE | VULNERABLE | SAFE |
| generated_sqlalchemy_text_safe_1 | SAFE | SAFE | VULNERABLE | VULNERABLE | SAFE |
| generated_sqlalchemy_text_dynamic_0 | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| generated_sqlalchemy_text_dynamic_1 | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |

## Multi-File Flask Projects

- Projects: 4
- Correct project-level classifications: 4/4

| Project | Category | Label | Prediction | Files | Errors | Findings |
|---|---|---|---|---:|---:|---:|
| project_multifile_vulnerable | route_service_repository | VULNERABLE | VULNERABLE | 4 | 0 | 1 |
| project_multifile_parameterized | route_service_parameterized | SAFE | SAFE | 2 | 0 | 0 |
| project_multifile_json_format | json_service_format | VULNERABLE | VULNERABLE | 2 | 0 | 1 |
| project_multifile_sanitized | service_sanitized | SAFE | SAFE | 2 | 0 | 0 |


## Scope

This Flask profile models common request sources, DB-API and SQLAlchemy raw-query sinks, import aliases, route decorators, f-strings, percent formatting, `.format()`, JSON body extraction through subscripts and `.get()`, and parameterized query patterns.
