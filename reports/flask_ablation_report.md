# Flask Ablation Study

This study disables SecureFlow components to estimate their contribution.

- `full`: interprocedural summaries and parameterized SQL modeling enabled.
- `no_interprocedural`: function summaries disabled.
- `no_parameterized_model`: parameterized SQL safety modeling disabled.
- `intraprocedural_no_parameterized_model`: both disabled.

| Variant | Dataset | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full | snippet | 38 | 0 | 20 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| full | project | 4 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| full | combined | 42 | 0 | 24 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| no_interprocedural | snippet | 37 | 0 | 20 | 1 | 1.000 | 0.974 | 0.987 | 0.983 |
| no_interprocedural | project | 1 | 1 | 3 | 3 | 0.500 | 0.250 | 0.333 | 0.500 |
| no_interprocedural | combined | 38 | 1 | 23 | 4 | 0.974 | 0.905 | 0.938 | 0.924 |
| no_parameterized_model | snippet | 38 | 11 | 9 | 0 | 0.776 | 1.000 | 0.874 | 0.810 |
| no_parameterized_model | project | 4 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| no_parameterized_model | combined | 42 | 11 | 13 | 0 | 0.792 | 1.000 | 0.884 | 0.833 |
| intraprocedural_no_parameterized_model | snippet | 37 | 11 | 9 | 1 | 0.771 | 0.974 | 0.860 | 0.793 |
| intraprocedural_no_parameterized_model | project | 1 | 1 | 3 | 3 | 0.500 | 0.250 | 0.333 | 0.500 |
| intraprocedural_no_parameterized_model | combined | 38 | 12 | 12 | 4 | 0.760 | 0.905 | 0.826 | 0.758 |
