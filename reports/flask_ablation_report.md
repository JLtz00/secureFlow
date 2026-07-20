# Flask Ablation Study

This study disables SecureFlow components to estimate their contribution.

- `full`: interprocedural summaries and parameterized SQL modeling enabled.
- `no_interprocedural`: function summaries disabled.
- `no_parameterized_model`: parameterized SQL safety modeling disabled.
- `intraprocedural_no_parameterized_model`: both disabled.

| Variant | Dataset | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full | snippet | 34 | 0 | 18 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| full | project | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| full | combined | 36 | 0 | 20 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| no_interprocedural | snippet | 33 | 0 | 18 | 1 | 1.000 | 0.971 | 0.985 | 0.981 |
| no_interprocedural | project | 1 | 1 | 1 | 1 | 0.500 | 0.500 | 0.500 | 0.500 |
| no_interprocedural | combined | 34 | 1 | 19 | 2 | 0.971 | 0.944 | 0.958 | 0.946 |
| no_parameterized_model | snippet | 34 | 10 | 8 | 0 | 0.773 | 1.000 | 0.872 | 0.808 |
| no_parameterized_model | project | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| no_parameterized_model | combined | 36 | 10 | 10 | 0 | 0.783 | 1.000 | 0.878 | 0.821 |
| intraprocedural_no_parameterized_model | snippet | 33 | 10 | 8 | 1 | 0.767 | 0.971 | 0.857 | 0.788 |
| intraprocedural_no_parameterized_model | project | 1 | 1 | 1 | 1 | 0.500 | 0.500 | 0.500 | 0.500 |
| intraprocedural_no_parameterized_model | combined | 34 | 11 | 9 | 2 | 0.756 | 0.944 | 0.840 | 0.768 |
