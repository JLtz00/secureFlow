"""Sprint 7 - Part A: Reproducible benchmark dataset generator.

Generates 210 Python programs across 5 vulnerability categories and
writes per-file JSON metadata with ground-truth labels.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path

random.seed(42)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "data" / "dataset"

SOURCES = ["request.form.get", "request.args.get", "input"]
TABLES = ["users", "products", "orders", "accounts", "sessions"]
COLUMNS = ["id", "name", "email", "username", "token"]
FIELDS = ["field", "param", "value", "key", "data"]
FUNC_NAMES = ["get_param", "fetch_value", "read_input", "load_data", "obtain_val"]
VAR_NAMES = ["user", "uid", "name", "param", "val", "entry", "data"]


@dataclass
class DatasetEntry:
    file: str
    label: str        # "VULNERABLE" or "SAFE"
    category: str     # "A" | "B" | "C" | "D" | "E"
    vulnerability: str  # "SQLI" or "NONE"
    source_line: int
    sink_line: int


class DatasetGenerator:
    def __init__(self, output_dir: str | Path = DEFAULT_DATASET_DIR) -> None:
        self.output_dir = Path(output_dir)

    def generate(self, count: int = 210) -> list[DatasetEntry]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        entries: list[DatasetEntry] = []
        per_cat = count // 5

        generators = [
            (self._cat_a, "A", "VULNERABLE", per_cat),
            (self._cat_b, "B", "VULNERABLE", per_cat),
            (self._cat_c, "C", "SAFE",       per_cat),
            (self._cat_d, "D", "SAFE",       per_cat),
            (self._cat_e, "E", "VULNERABLE", count - 4 * per_cat),
        ]

        idx = 1
        for gen_fn, cat, label, n in generators:
            for i in range(n):
                code, src_line, sink_line = gen_fn(i)
                filename = f"case_{idx:03d}.py"
                (self.output_dir / filename).write_text(code)
                entries.append(DatasetEntry(
                    file=filename,
                    label=label,
                    category=cat,
                    vulnerability="SQLI" if label == "VULNERABLE" else "NONE",
                    source_line=src_line,
                    sink_line=sink_line,
                ))
                idx += 1

        metadata_path = self.output_dir.parent / "dataset_metadata.json"
        metadata_path.write_text(
            json.dumps([asdict(e) for e in entries], indent=2)
        )
        return entries

    # ---------------------------------------------------------------- Cat A
    # Direct SQL injection: tainted variable directly in execute()

    def _cat_a(self, seed: int) -> tuple[str, int, int]:
        src = SOURCES[seed % len(SOURCES)]
        tbl = TABLES[seed % len(TABLES)]
        col = COLUMNS[seed % len(COLUMNS)]
        var = VAR_NAMES[seed % len(VAR_NAMES)]
        fld = FIELDS[seed % len(FIELDS)]
        lines = [
            f'{var} = {src}("{fld}")',
            f'cursor.execute("SELECT * FROM {tbl} WHERE {col} = " + {var})',
        ]
        return "\n".join(lines) + "\n", 1, 2

    # ---------------------------------------------------------------- Cat B
    # Interprocedural: taint flows through a user-defined function

    def _cat_b(self, seed: int) -> tuple[str, int, int]:
        src = SOURCES[seed % len(SOURCES)]
        tbl = TABLES[seed % len(TABLES)]
        col = COLUMNS[seed % len(COLUMNS)]
        fn = FUNC_NAMES[seed % len(FUNC_NAMES)]
        var = VAR_NAMES[seed % len(VAR_NAMES)]
        fld = FIELDS[seed % len(FIELDS)]
        lines = [
            f"def {fn}():",
            f'    return {src}("{fld}")',
            "",
            f"{var} = {fn}()",
            f'cursor.execute("SELECT * FROM {tbl} WHERE {col} = " + {var})',
        ]
        return "\n".join(lines) + "\n", 2, 5

    # ---------------------------------------------------------------- Cat C
    # Sanitized: taint is cleared before reaching the sink

    def _cat_c(self, seed: int) -> tuple[str, int, int]:
        src = SOURCES[seed % len(SOURCES)]
        tbl = TABLES[seed % len(TABLES)]
        col = COLUMNS[seed % len(COLUMNS)]
        var = VAR_NAMES[seed % len(VAR_NAMES)]
        san = "sanitize" if seed % 2 == 0 else "escape"
        fld = FIELDS[seed % len(FIELDS)]
        lines = [
            f'raw = {src}("{fld}")',
            f"{var} = {san}(raw)",
            f'cursor.execute("SELECT * FROM {tbl} WHERE {col} = " + {var})',
        ]
        return "\n".join(lines) + "\n", 1, 3

    # ---------------------------------------------------------------- Cat D
    # Parameterized query: safe by design, no string concatenation at sink

    def _cat_d(self, seed: int) -> tuple[str, int, int]:
        src = SOURCES[seed % len(SOURCES)]
        tbl = TABLES[seed % len(TABLES)]
        col = COLUMNS[seed % len(COLUMNS)]
        var = VAR_NAMES[seed % len(VAR_NAMES)]
        fld = FIELDS[seed % len(FIELDS)]
        lines = [
            f'{var} = {src}("{fld}")',
            f'cursor.execute("SELECT * FROM {tbl} WHERE {col} = ?", ({var},))',
        ]
        return "\n".join(lines) + "\n", 1, 2

    # ---------------------------------------------------------------- Cat E
    # Complex flow: taint through branches, loops, aliases, multi-assignment

    def _cat_e(self, seed: int) -> tuple[str, int, int]:
        variant = seed % 4
        tbl = TABLES[seed % len(TABLES)]
        col = COLUMNS[seed % len(COLUMNS)]
        var = VAR_NAMES[seed % len(VAR_NAMES)]
        src = SOURCES[seed % len(SOURCES)]
        fld = FIELDS[seed % len(FIELDS)]

        if variant == 0:  # through if branch
            lines = [
                f'{var} = {src}("{fld}")',
                f"flag = 1",
                f"if flag:",
                f"    query = {var}",
                f'cursor.execute("SELECT * FROM {tbl} WHERE {col} = " + query)',
            ]
            return "\n".join(lines) + "\n", 1, 5

        if variant == 1:  # through while loop
            lines = [
                f'{var} = {src}("{fld}")',
                f"count = 0",
                f"while count < 1:",
                f"    query = {var}",
                f"    count = count + 1",
                f'cursor.execute("SELECT * FROM {tbl} WHERE {col} = " + query)',
            ]
            return "\n".join(lines) + "\n", 1, 6

        if variant == 2:  # alias chain
            lines = [
                f'{var} = {src}("{fld}")',
                f"a = {var}",
                f"b = a",
                f'cursor.execute("SELECT * FROM {tbl} WHERE {col} = " + b)',
            ]
            return "\n".join(lines) + "\n", 1, 4

        # variant 3: string concatenation builds query in parts
        lines = [
            f'{var} = {src}("{fld}")',
            f'prefix = "SELECT * FROM {tbl} WHERE {col} = "',
            f"query = prefix + {var}",
            f"cursor.execute(query)",
        ]
        return "\n".join(lines) + "\n", 1, 4


def main() -> None:
    gen = DatasetGenerator()
    entries = gen.generate(210)
    vuln = sum(1 for e in entries if e.label == "VULNERABLE")
    safe = sum(1 for e in entries if e.label == "SAFE")
    print(f"Generated {len(entries)} programs — {vuln} VULNERABLE, {safe} SAFE")
    print(f"Metadata written to {gen.output_dir.parent / 'dataset_metadata.json'}")


if __name__ == "__main__":
    main()
