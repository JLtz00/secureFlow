# Real Flask Baselines

## Tool Versions

- Bandit: bandit 1.9.4
- Semgrep: 1.170.0

## Metrics

The total row combines snippets and projects; it is not a separate dataset.

| Tool | Evaluation set | Status | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Bandit | Flask snippets | OK | 37 | 7 | 13 | 1 | 0.841 | 0.974 | 0.902 | 0.862 |
| Bandit | Flask projects | OK | 4 | 1 | 3 | 0 | 0.800 | 1.000 | 0.889 | 0.875 |
| Bandit | Total (snippets + projects) | OK | 41 | 8 | 16 | 1 | 0.837 | 0.976 | 0.901 | 0.864 |
| Semgrep | Flask snippets | OK | 2 | 7 | 13 | 36 | 0.222 | 0.053 | 0.085 | 0.259 |
| Semgrep | Flask projects | OK | 0 | 1 | 3 | 4 | 0.000 | 0.000 | 0.000 | 0.375 |
| Semgrep | Total (snippets + projects) | OK | 2 | 8 | 16 | 40 | 0.200 | 0.048 | 0.077 | 0.273 |
