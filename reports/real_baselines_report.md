# Real Flask Baselines

## Tool Versions

- Bandit: bandit 1.9.4
- Semgrep: 1.170.0

## Metrics

| Tool | Dataset | Status | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Bandit | flask_snippet | OK | 34 | 7 | 11 | 0 | 0.829 | 1.000 | 0.907 | 0.865 |
| Bandit | flask_project | OK | 2 | 1 | 1 | 0 | 0.667 | 1.000 | 0.800 | 0.750 |
| Bandit | combined | OK | 36 | 8 | 12 | 0 | 0.818 | 1.000 | 0.900 | 0.857 |
| Semgrep | flask_snippet | OK | 2 | 7 | 11 | 32 | 0.222 | 0.059 | 0.093 | 0.250 |
| Semgrep | flask_project | OK | 0 | 1 | 1 | 2 | 0.000 | 0.000 | 0.000 | 0.250 |
| Semgrep | combined | OK | 2 | 8 | 12 | 34 | 0.200 | 0.056 | 0.087 | 0.250 |
