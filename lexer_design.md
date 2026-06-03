# SecureFlow Lexer Design

## Goal

Sprint 01 implements a production-oriented lexical analyzer for the Python subset needed by SecureFlow's parser and taint-analysis pipeline.

## Public API

- `TokenType`: enum of stable token categories.
- `Token`: immutable dataclass with `type`, `value`, `line`, and `column`.
- `Lexer.tokenize(source)`: scans a source string and returns a complete token list ending in `EOF`.
- `tokenize(source)`: convenience function.

## Token Categories

- `KEYWORD`: Python control-flow and declaration words such as `def`, `if`, `return`, `for`, `while`, `True`, `False`, and `None`.
- `IDENTIFIER`: names used for variables, functions, attributes, and modules.
- `NUMBER`: integer, float, binary, octal, and hexadecimal numeric literals.
- `STRING`: single-quoted, double-quoted, and triple-quoted string literals.
- `FSTRING`: string literals with an `f`, `fr`, or `rf` prefix.
- `OPERATOR`: arithmetic, comparison, assignment, attribute access, and arrow operators.
- `DELIMITER`: parentheses, brackets, braces, comma, colon, and semicolon.
- `INDENT`, `DEDENT`, `NEWLINE`, `EOF`: layout tokens for the recursive-descent parser.
- `ERROR`: malformed or unsupported input. Scanning continues after an error token.

## Scanning Strategy

The lexer is a regex-based scanner with a small amount of state for Python layout:

1. At the beginning of each logical line, leading spaces and tabs are converted into an indentation width.
2. The width is compared with an indentation stack to emit `INDENT` and `DEDENT`.
3. Blank lines and comment-only lines do not affect indentation.
4. Comments are skipped and are not emitted as tokens.
5. Bracket depth suppresses layout handling inside `()`, `[]`, and `{}`.
6. Regexes recognize identifiers, numbers, and string prefixes.
7. Strings are scanned with delimiter-aware logic so triple-quoted multi-line strings preserve their full value and update source positions correctly.

## Error Recovery

Unknown characters are emitted as `ERROR` tokens and skipped. Unterminated single-line strings are also emitted as `ERROR`, then scanning resumes at the next line. This gives the parser enough information to report useful diagnostics without losing the rest of the file.

## Future Parser Contract

Sprint 02 can consume this stream directly:

- Function and block structure comes from `KEYWORD`, `DELIMITER`, `NEWLINE`, `INDENT`, and `DEDENT`.
- Calls such as `request.args.get()` are represented as identifiers plus `.` operators and call delimiters.
- Source-to-sink traces can rely on every token carrying a 1-based line and column.
