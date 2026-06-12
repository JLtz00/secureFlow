"""End-to-end demo for SecureFlow Sprints 01 through 04.

Run with:
    python3 -m demos.demo_secureflow
"""

from __future__ import annotations

from pathlib import Path

from analyzer.ast_visualizer import visualize
from analyzer.cfg_builder import build_cfg
from analyzer.cfg_visualizer import visualize_cfg
from analyzer.ir import format_module
from analyzer.ir_generator import generate_ir
from analyzer.lexer import Lexer, TokenType
from analyzer.parser import Parser
from analyzer.semantic import analyze


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_FILE = PROJECT_ROOT / "examples" / "vulnerable_query.py"
DEMO_SOURCE = DEMO_FILE.read_text(encoding="utf-8")


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


def explain_next_step() -> None:
    print_section("7. Que demuestra esto")
    print(
        "- El lexer reconoce palabras, identificadores, strings, operadores y posiciones."
    )
    print("- El parser construye un AST propio sin usar el modulo ast de Python.")
    print("- El analizador semantico crea scopes y una tabla de simbolos.")
    print("- Tambien marca taint inicial cuando ve fuentes como request.args.get.")
    print("- El generador IR transforma expresiones en instrucciones de tres direcciones.")
    print("- El CFG separa ramas y saltos en bloques basicos conectados por aristas.")
    print(
        "- Todavia no declara vulnerabilidad SQL Injection; eso vendra con el motor de taint."
    )


def main() -> None:
    show_source()
    show_tokens()
    show_ast()
    show_semantic_analysis()
    show_ir()
    show_cfg()
    explain_next_step()


if __name__ == "__main__":
    main()
