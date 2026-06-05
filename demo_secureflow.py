"""Small end-to-end demo for Sprint 01, Sprint 02 and Sprint 03.

Run with:
    python3 demo_secureflow.py
"""

from __future__ import annotations

from ast_visualizer import visualize
from lexer import Lexer, TokenType
from parser import Parser
from semantic import analyze


DEMO_SOURCE = """def build_query(user):
    query = \"SELECT * FROM users WHERE name=\" + user
    return query

user = request.args.get(\"user\")
query = build_query(user)
cursor.execute(query)
"""


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
        if token.type not in {TokenType.NEWLINE, TokenType.INDENT, TokenType.DEDENT, TokenType.EOF}
    ]

    print(f"{'TYPE':<12} {'VALUE':<36} {'LINE':>4} {'COL':>4}")
    print("-" * 62)
    for token in visible_tokens:
        value = token.value.replace("\\n", "\\\\n")
        if len(value) > 34:
            value = value[:31] + "..."
        print(f"{token.type.value:<12} {value:<36} {token.line:>4} {token.column:>4}")

    layout = [token.type.value for token in tokens if token.type in {TokenType.INDENT, TokenType.DEDENT}]
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
            print(f"- {error.line}:{error.column}: {error.message} cerca de {error.token_value!r}")
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


def explain_next_step() -> None:
    print_section("5. Que demuestra esto")
    print("- El lexer reconoce palabras, identificadores, strings, operadores y posiciones.")
    print("- El parser construye un AST propio sin usar el modulo ast de Python.")
    print("- El analizador semantico crea scopes y una tabla de simbolos.")
    print("- Tambien marca taint inicial cuando ve fuentes como request.args.get.")
    print("- Todavia no declara vulnerabilidad SQL Injection; eso vendra con el motor de taint.")


def main() -> None:
    show_source()
    show_tokens()
    show_ast()
    show_semantic_analysis()
    explain_next_step()


if __name__ == "__main__":
    main()
