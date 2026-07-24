"""End-to-end presentation demo for SecureFlow.

Run with:
    python3 -m demos.demo_secureflow
"""

from __future__ import annotations

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
from analyzer.project_scanner import ProjectScanner
from analyzer.reporter import Reporter
from analyzer.semantic import analyze
from analyzer.taint_engine import TaintResult, analyze_cfg


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_FILE = PROJECT_ROOT / "examples" / "vulnerable_query.py"
DEMO_SOURCE = DEMO_FILE.read_text(encoding="utf-8")
FLASK_DEMO_PROJECT = PROJECT_ROOT / "data" / "flask_projects" / "project_multifile_vulnerable"


def print_section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def show_source() -> None:
    print_section("1. Codigo Python de entrada")
    print(DEMO_SOURCE)


def show_tokens() -> None:
    print_section("2. Lexer: codigo convertido a tokens")
    lexer = Lexer()
    tokens = lexer.tokenize(DEMO_SOURCE)
    visible_tokens = [
        token
        for token in tokens
        if token.type
        not in {TokenType.NEWLINE, TokenType.INDENT, TokenType.DEDENT, TokenType.EOF}
    ]

    print(f"{'TYPE':<12} {'VALUE':<36} {'LINE':>4} {'COL':>4}")
    print("-" * 62)
    for token in visible_tokens:
        value = token.value.replace("\\n", "\\\\n")
        if len(value) > 34:
            value = value[:31] + "..."
        print(f"{token.type.value:<12} {value:<36} {token.line:>4} {token.column:>4}")

    layout = [
        token.type.value
        for token in tokens
        if token.type in {TokenType.INDENT, TokenType.DEDENT}
    ]
    print()
    print("Tokens de bloque encontrados:", ", ".join(layout) or "ninguno")


def parse_demo():
    parser = Parser.from_source(DEMO_SOURCE)
    program = parser.parse()
    return parser, program


def show_ast() -> None:
    print_section("3. Parser: tokens convertidos a AST propio")
    parser, program = parse_demo()
    print(visualize(program))

    print()
    if parser.errors:
        print("Errores encontrados:")
        for error in parser.errors:
            print(
                f"- {error.line}:{error.column}: {error.message} cerca de {error.token_value!r}"
            )
    else:
        print("Resultado: el parser no encontro errores sintacticos.")


def show_semantic_analysis() -> None:
    print_section("4. Semantico: scopes, tipos y taint inicial")
    _, program = parse_demo()
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

    if result.issues:
        print()
        print("Advertencias semanticas:")
        for issue in result.issues:
            print(f"- {issue.line}:{issue.column}: {issue.message} {issue.name!r}")
    else:
        print()
        print("Resultado: no hay nombres sin resolver en este ejemplo.")



def show_ir() -> None:
    print_section("5. IR: codigo de tres direcciones (TAC)")
    _, program = parse_demo()
    module = generate_ir(program)
    print(format_module(module))


def show_cfg() -> None:
    print_section("6. CFG: bloques basicos y aristas de control")
    _, program = parse_demo()
    module = generate_ir(program)
    for function in module.all_functions():
        cfg = build_cfg(function.instructions, function.name)
        print(visualize_cfg(cfg))
        print()


def _run_taint_analysis():
    _, program = parse_demo()
    module = generate_ir(program)
    summaries = analyze_module(module)
    combined = TaintResult()
    instructions_by_function = {}

    for function in module.all_functions():
        instructions_by_function[function.name] = function.instructions
        cfg = build_cfg(function.instructions, function.name)
        result = analyze_cfg(cfg, summaries=summaries)
        combined.vulnerabilities.extend(result.vulnerabilities)
        combined.block_out.update(result.block_out)

    return module, combined, instructions_by_function


def show_taint_result() -> None:
    print_section("7. Taint analysis: deteccion real de SQL Injection")
    _, result, instructions_by_function = _run_taint_analysis()

    if not result.vulnerabilities:
        print("Resultado: no se detectaron vulnerabilidades.")
        return

    print(f"Vulnerabilidades detectadas: {len(result.vulnerabilities)}")
    reporter = Reporter()
    for index, vulnerability in enumerate(result.vulnerabilities, start=1):
        print()
        print(f"[{index}] {vulnerability}")
        trace = reporter.generate_trace(
            vulnerability,
            instructions_by_function.get("<main>", []),
        )
        print(trace.format())


def show_hardening() -> None:
    print_section("8. Hardening automatico: consulta vulnerable a parametrizada")
    vulnerable_line = 'cursor.execute("SELECT * FROM users WHERE name=" + user)\n'
    hardened = harden_source(vulnerable_line)

    print("Original:")
    print(vulnerable_line.rstrip())
    print()
    print("Corregido:")
    print(hardened.source.rstrip())
    print()
    print(f"Lineas modificadas: {hardened.modified_lines}")


def show_flask_project_scan() -> None:
    print_section("9. Scanner Flask multiarchivo")
    result = ProjectScanner(FLASK_DEMO_PROJECT).scan()

    print(f"Proyecto: {FLASK_DEMO_PROJECT.relative_to(PROJECT_ROOT)}")
    print(f"Archivos analizados: {result.files_analyzed}/{result.files_total}")
    print(f"Funciones analizadas: {result.functions_analyzed}")
    print(f"Hallazgos: {len(result.findings)}")
    for finding in result.findings:
        sources = ", ".join(finding.sources)
        print(
            f"- {finding.severity} {finding.rule_id}: {finding.file}:{finding.line} "
            f"{finding.function}() -> {finding.sink} "
            f"(fuentes: {sources})"
        )


def explain_result() -> None:
    print_section("10. Que demuestra esto")
    print(
        "- El lexer reconoce palabras, identificadores, strings, operadores y posiciones."
    )
    print("- El parser construye un AST propio sin usar el modulo ast de Python.")
    print("- El analizador semantico crea scopes y una tabla de simbolos.")
    print("- Tambien marca taint inicial cuando ve fuentes como request.args.get.")
    print("- El generador IR transforma expresiones en instrucciones de tres direcciones.")
    print("- El CFG separa ramas y saltos en bloques basicos conectados por aristas.")
    print("- El motor de taint detecta SQL Injection con resumenes interprocedurales.")
    print("- El scanner Flask encuentra el flujo vulnerable incluso en un proyecto multiarchivo.")
    print("- El hardener muestra como convertir concatenacion SQL en consulta parametrizada.")


def main() -> None:
    show_source()
    show_tokens()
    show_ast()
    show_semantic_analysis()
    show_ir()
    show_cfg()
    show_taint_result()
    show_hardening()
    show_flask_project_scan()
    explain_result()


if __name__ == "__main__":
    main()
