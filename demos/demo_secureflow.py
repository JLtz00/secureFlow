"""End-to-end demonstration for SecureFlow Sprints 01 through 07.

Run with:
    python3 -m demos.demo_secureflow
"""

from __future__ import annotations

import json
from pathlib import Path

from analyzer.ast_visualizer import visualize
from analyzer.cfg_builder import build_cfg
from analyzer.cfg_visualizer import visualize_cfg
from analyzer.hardener import harden_source
from analyzer.interprocedural import analyze_module
from analyzer.ir import format_module
from analyzer.ir_generator import generate_ir
from analyzer.lexer import Lexer, TokenType
from analyzer.parser import Parser
from analyzer.reporter import Reporter
from analyzer.semantic import analyze
from analyzer.taint_engine import analyze_cfg


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_FILE = PROJECT_ROOT / "examples" / "vulnerable_query.py"
DATASET_METADATA = PROJECT_ROOT / "data" / "dataset_metadata.json"
BENCHMARK_SUMMARY = PROJECT_ROOT / "reports" / "final" / "summary.json"
DEMO_SOURCE = DEMO_FILE.read_text(encoding="utf-8")


def print_section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def build_pipeline():
    parser = Parser.from_source(DEMO_SOURCE)
    program = parser.parse()
    module = generate_ir(program)
    return parser, program, module


def show_source() -> None:
    print_section("1. Codigo Python de entrada")
    print(DEMO_SOURCE)


def show_tokens() -> None:
    print_section("2. Sprint 1: analisis lexico")
    tokens = Lexer().tokenize(DEMO_SOURCE)
    visible = [
        token
        for token in tokens
        if token.type
        not in {TokenType.NEWLINE, TokenType.INDENT, TokenType.DEDENT, TokenType.EOF}
    ]
    print(f"{'TYPE':<12} {'VALUE':<36} {'LINE':>4} {'COL':>4}")
    print("-" * 62)
    for token in visible:
        value = token.value.replace("\n", "\\n")
        if len(value) > 34:
            value = value[:31] + "..."
        print(f"{token.type.value:<12} {value:<36} {token.line:>4} {token.column:>4}")


def show_ast() -> None:
    print_section("3. Sprint 2: AST propio")
    parser, program, _ = build_pipeline()
    print(visualize(program))
    print()
    print(f"Errores sintacticos: {len(parser.errors)}")


def show_semantic_analysis() -> None:
    print_section("4. Sprint 3: scopes, tipos y taint inicial")
    _, program, _ = build_pipeline()
    result = analyze(program)
    print(f"{'SCOPE':<14} {'NAME':<16} {'KIND':<10} {'TYPE':<8} {'TAINT':<7} SOURCE")
    print("-" * 78)
    for symbol in result.symbols.all_symbols():
        taint = "SI" if symbol.is_tainted else "NO"
        sources = ", ".join(symbol.taint_sources) or "-"
        print(
            f"{symbol.scope_name:<14} {symbol.name:<16} {symbol.kind:<10} "
            f"{symbol.type_name:<8} {taint:<7} {sources}"
        )


def show_ir_and_cfg() -> None:
    print_section("5. Sprint 4: IR de tres direcciones y CFG")
    _, _, module = build_pipeline()
    print(format_module(module))
    print()
    for function in module.all_functions():
        cfg = build_cfg(function.instructions, function.name)
        print(visualize_cfg(cfg))
        print()


def show_taint_analysis() -> None:
    print_section("6. Sprint 5: motor de taint con worklist")
    _, _, module = build_pipeline()
    cfg = build_cfg(module.main.instructions, module.main.name)
    result = analyze_cfg(cfg)
    print(f"Bloques analizados: {len(cfg.blocks)}")
    print(f"Vulnerabilidades detectadas: {len(result.vulnerabilities)}")
    for vulnerability in result.vulnerabilities:
        print(f"- {vulnerability}")


def show_sprint_6() -> None:
    print_section("7. Sprint 6: interprocedural, traza y hardening")
    _, _, module = build_pipeline()
    summaries = analyze_module(module)
    print("Resumenes de funciones:")
    for summary in summaries.values():
        print(
            f"- {summary.name}: returns_tainted={summary.returns_tainted}, "
            f"taints_arguments={summary.taints_arguments}, "
            f"returns_sanitized={summary.returns_sanitized}"
        )

    cfg = build_cfg(module.main.instructions, module.main.name)
    taint_result = analyze_cfg(cfg)
    if taint_result.vulnerabilities:
        print("\nTraza explicable:")
        trace = Reporter().generate_trace(
            taint_result.vulnerabilities[0], module.main.instructions
        )
        print(trace.format())

    vulnerable_line = 'cursor.execute("SELECT * FROM users WHERE name=" + user)\n'
    hardened = harden_source(vulnerable_line)
    print("\nEndurecimiento automatico:")
    print("ANTES:", vulnerable_line.strip())
    print("DESPUES:", hardened.source.strip())
    print(f"Cambios realizados: {hardened.changes_made}")


def show_sprint_7() -> None:
    print_section("8. Sprint 7: dataset y evaluacion experimental")
    metadata = json.loads(DATASET_METADATA.read_text(encoding="utf-8"))
    summary = json.loads(BENCHMARK_SUMMARY.read_text(encoding="utf-8"))
    vulnerable = sum(item["label"] == "VULNERABLE" for item in metadata)
    safe = len(metadata) - vulnerable
    print(f"Dataset reproducible: {len(metadata)} programas")
    print(f"Ground truth: {vulnerable} vulnerables, {safe} seguros")
    print()
    print(f"{'TOOL':<12} {'PRECISION':>10} {'RECALL':>8} {'F1':>8} {'ACCURACY':>10}")
    print("-" * 54)
    for tool, metrics in summary.items():
        print(
            f"{tool:<12} {metrics['precision']:>10.4f} "
            f"{metrics['recall']:>8.4f} {metrics['f1']:>8.4f} "
            f"{metrics['accuracy']:>10.4f}"
        )
    print("\nInforme completo: reports/research_report.md")


def show_conclusion() -> None:
    print_section("9. Resultado del proyecto")
    print("Codigo -> Tokens -> AST -> Semantica -> IR -> CFG -> Taint")
    print("       -> Traza explicable -> Hardening -> Evaluacion experimental")


def main() -> None:
    show_source()
    show_tokens()
    show_ast()
    show_semantic_analysis()
    show_ir_and_cfg()
    show_taint_analysis()
    show_sprint_6()
    show_sprint_7()
    show_conclusion()


if __name__ == "__main__":
    main()
