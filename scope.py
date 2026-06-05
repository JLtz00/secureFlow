"""Nested scope and symbol table support."""

from __future__ import annotations

from dataclasses import dataclass, field

from symbols import Symbol


@dataclass
class Scope:
    name: str
    kind: str
    parent: "Scope | None" = None
    symbols: dict[str, Symbol] = field(default_factory=dict)
    children: list["Scope"] = field(default_factory=list)

    def define(self, symbol: Symbol) -> Symbol:
        symbol.scope_name = self.name
        self.symbols[symbol.name] = symbol
        return symbol

    def resolve_local(self, name: str) -> Symbol | None:
        return self.symbols.get(name)

    def resolve(self, name: str) -> Symbol | None:
        scope: Scope | None = self
        while scope is not None:
            symbol = scope.resolve_local(name)
            if symbol is not None:
                return symbol
            scope = scope.parent
        return None

    def create_child(self, name: str, kind: str) -> "Scope":
        child = Scope(name=name, kind=kind, parent=self)
        self.children.append(child)
        return child

    def all_symbols(self) -> list[Symbol]:
        result = list(self.symbols.values())
        for child in self.children:
            result.extend(child.all_symbols())
        return result


@dataclass
class SymbolTable:
    global_scope: Scope = field(default_factory=lambda: Scope("global", "global"))

    def all_symbols(self) -> list[Symbol]:
        return self.global_scope.all_symbols()

    def resolve(self, name: str) -> Symbol | None:
        return self.global_scope.resolve(name)

