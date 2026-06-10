"""Sprint 7 - Part H: Result visualization.

Reads benchmark and performance JSON files and generates publication-ready
ASCII tables (paper_tables/) and CSV data files (paper_figures/).
Does not require matplotlib — all output is plain text / CSV.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from analyzer.metrics import ConfusionMatrix, evaluate


def _load_json(path: str) -> list[dict]:
    return json.loads(Path(path).read_text())


def _cm_for_tool(records: list[dict], tool: str) -> ConfusionMatrix:
    predicted = {r["file"] for r in records if r["tool"] == tool and r["prediction"] == "VULNERABLE"}
    actual    = {r["file"] for r in records if r["tool"] == tool and r["ground_truth"]  == "VULNERABLE"}
    universe  = {r["file"] for r in records if r["tool"] == tool}
    return evaluate(predicted, actual, universe)


def _avg_time(records: list[dict], tool: str) -> float:
    times = [r["execution_time_ms"] for r in records if r["tool"] == tool]
    return sum(times) / len(times) if times else 0.0


class Visualizer:
    TOOLS = ["SecureFlow", "Bandit", "Semgrep", "Pysa"]

    def __init__(
        self,
        benchmark_file: str = "benchmark_results.json",
        performance_file: str = "performance_report.json",
    ) -> None:
        self.records = _load_json(benchmark_file)
        try:
            self.perf = _load_json(performance_file)
        except FileNotFoundError:
            self.perf = []
        Path("paper_tables").mkdir(exist_ok=True)
        Path("paper_figures").mkdir(exist_ok=True)
        Path("final_results").mkdir(exist_ok=True)

    def generate_all(self) -> None:
        self._table_detection_performance()
        self._table_execution_time()
        self._table_false_positives()
        self._csv_metrics_comparison()
        self._csv_performance_by_batch()
        self._write_final_summary()
        print("Visualization complete:")
        print("  paper_tables/  — detection, execution time, false positive tables")
        print("  paper_figures/ — CSV data for precision, recall, F1, FPR charts")
        print("  final_results/ — summary JSON")

    # ---------------------------------------------------------- tables

    def _table_detection_performance(self) -> None:
        header = f"{'Tool':<12} {'Precision':>9} {'Recall':>7} {'F1':>7} {'Accuracy':>9}"
        sep = "-" * len(header)
        rows = [header, sep]
        for tool in self.TOOLS:
            cm = _cm_for_tool(self.records, tool)
            rows.append(
                f"{tool:<12} {cm.precision:>9.3f} {cm.recall:>7.3f} "
                f"{cm.f1_score:>7.3f} {cm.accuracy:>9.3f}"
            )
        content = "\n".join(rows) + "\n"
        Path("paper_tables/table1_detection_performance.txt").write_text(content)

    def _table_execution_time(self) -> None:
        header = f"{'Tool':<12} {'Avg Time (ms)':>14}"
        sep = "-" * len(header)
        rows = [header, sep]
        for tool in self.TOOLS:
            avg = _avg_time(self.records, tool)
            rows.append(f"{tool:<12} {avg:>14.3f}")
        Path("paper_tables/table2_execution_time.txt").write_text("\n".join(rows) + "\n")

    def _table_false_positives(self) -> None:
        header = f"{'Tool':<12} {'FP':>4} {'FPR':>7} {'FNR':>7}"
        sep = "-" * len(header)
        rows = [header, sep]
        for tool in self.TOOLS:
            cm = _cm_for_tool(self.records, tool)
            rows.append(f"{tool:<12} {cm.fp:>4} {cm.fpr:>7.3f} {cm.fnr:>7.3f}")
        Path("paper_tables/table3_false_positives.txt").write_text("\n".join(rows) + "\n")

    # ---------------------------------------------------------- CSVs

    def _csv_metrics_comparison(self) -> None:
        with open("paper_figures/metrics_comparison.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["tool", "precision", "recall", "f1", "accuracy", "fpr", "fnr"])
            for tool in self.TOOLS:
                cm = _cm_for_tool(self.records, tool)
                w.writerow([tool, cm.precision, cm.recall, cm.f1_score,
                             cm.accuracy, cm.fpr, cm.fnr])

    def _csv_performance_by_batch(self) -> None:
        if not self.perf:
            return
        with open("paper_figures/performance_by_batch.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["batch_size", "avg_total_ms", "peak_memory_kb",
                         "lexer_ms", "parser_ms", "semantic_ms",
                         "ir_ms", "cfg_ms", "taint_ms"])
            for r in self.perf:
                s = r["avg_stage"]
                w.writerow([r["batch_size"], r["avg_total_ms"], r["peak_memory_kb"],
                             s["lexer_ms"], s["parser_ms"], s["semantic_ms"],
                             s["ir_ms"], s["cfg_ms"], s["taint_ms"]])

    def _write_final_summary(self) -> None:
        summary = {}
        for tool in self.TOOLS:
            cm = _cm_for_tool(self.records, tool)
            summary[tool] = {
                "tp": cm.tp, "fp": cm.fp, "tn": cm.tn, "fn": cm.fn,
                "precision": round(cm.precision, 4),
                "recall":    round(cm.recall,    4),
                "f1":        round(cm.f1_score,  4),
                "accuracy":  round(cm.accuracy,  4),
                "fpr":       round(cm.fpr, 4),
                "fnr":       round(cm.fnr, 4),
                "avg_time_ms": round(_avg_time(self.records, tool), 4),
            }
        Path("final_results/summary.json").write_text(json.dumps(summary, indent=2))


def main() -> None:
    v = Visualizer()
    v.generate_all()


if __name__ == "__main__":
    main()
