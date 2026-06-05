"""Small end-to-end demo for Sprint 01 and Sprint 02.

Run with:
    python3 demo_secureflow.py
"""

from __future__ import annotations

from ast_visualizer import visualize
from lexer import Lexer, TokenType
from parser import Parser


DEMO_SOURCE = """def get_user():
    user = request.args.get("user")
    return user

query = "SELECT * FROM users WHERE name='" + get_user()
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
        value = token.value.replace("\n", "\\n")
        if len(value) > 34:
            value = value[:31] + "..."
        print(f"{token.type.value:<12} {value:<36} {token.line:>4} {token.column:>4}")

    layout = [token.type.value for token in tokens if token.type in {TokenType.INDENT, TokenType.DEDENT}]
    print()
    print("Tokens de bloque encontrados:", ", ".join(layout) or "ninguno")


def show_ast() -> None:
    print_section("3. Parser: tokens convertidos a AST propio")
    parser = Parser.from_source(DEMO_SOURCE)
    program = parser.parse()
    print(visualize(program))

    print()
    if parser.errors:
        print("Errores encontrados:")
        for error in parser.errors:
            print(f"- {error.line}:{error.column}: {error.message} cerca de {error.token_value!r}")
    else:
        print("Resultado: el parser no encontro errores sintacticos.")


def explain_next_step() -> None:
    print_section("4. Que demuestra esto")
    print("- El lexer reconoce palabras, identificadores, strings, operadores y posiciones.")
    print("- El parser construye un AST propio sin usar el modulo ast de Python.")
    print("- El AST ya deja visibles una fuente, una propagacion y un sink:")
    print("  fuente: request.args.get")
    print("  propagacion: get_user() -> query")
    print("  sink: cursor.execute")
    print("- En el Sprint 03, el analisis semantico usara este AST para marcar taint.")


def main() -> None:
    show_source()
    show_tokens()
    show_ast()
    explain_next_step()


if __name__ == "__main__":
    main()
