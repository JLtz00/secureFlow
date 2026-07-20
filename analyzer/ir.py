"""Three-address intermediate representation for SecureFlow."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Instruction:
    line: int


@dataclass
class Label(Instruction):
    name: str

    def __str__(self) -> str:
        return f"{self.name}:"


@dataclass
class Assign(Instruction):
    target: str
    value: str

    def __str__(self) -> str:
        return f"{self.target} = {self.value}"


@dataclass
class BinaryOp(Instruction):
    target: str
    left: str
    operator: str
    right: str

    def __str__(self) -> str:
        return f"{self.target} = {self.left} {self.operator} {self.right}"


@dataclass
class BuildCollection(Instruction):
    target: str
    kind: str
    elements: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.target} = {self.kind}({', '.join(self.elements)})"


@dataclass
class BuildFString(Instruction):
    target: str
    raw: str
    fields: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.target} = fstring({', '.join(self.fields)})"


@dataclass
class Subscript(Instruction):
    target: str
    collection: str
    index: str

    def __str__(self) -> str:
        return f"{self.target} = {self.collection}[{self.index}]"


@dataclass
class UnaryOp(Instruction):
    target: str
    operator: str
    operand: str

    def __str__(self) -> str:
        return f"{self.target} = {self.operator} {self.operand}"


@dataclass
class Call(Instruction):
    function: str
    args: list[str] = field(default_factory=list)
    target: str | None = None

    def __str__(self) -> str:
        call = f"call {self.function}({', '.join(self.args)})"
        return call if self.target is None else f"{self.target} = {call}"


@dataclass
class Jump(Instruction):
    target: str

    def __str__(self) -> str:
        return f"jump {self.target}"


@dataclass
class ConditionalJump(Instruction):
    condition: str
    true_target: str
    false_target: str

    def __str__(self) -> str:
        return f"if {self.condition} jump {self.true_target} else {self.false_target}"


@dataclass
class Return(Instruction):
    value: str | None = None

    def __str__(self) -> str:
        return "return" if self.value is None else f"return {self.value}"


@dataclass
class IRFunction:
    name: str
    params: list[str]
    instructions: list[Instruction] = field(default_factory=list)


@dataclass
class IRModule:
    main: IRFunction = field(default_factory=lambda: IRFunction("<main>", []))
    functions: dict[str, IRFunction] = field(default_factory=dict)

    def all_functions(self) -> list[IRFunction]:
        return [self.main, *self.functions.values()]


def format_instructions(instructions: list[Instruction]) -> str:
    return "\n".join(f"{index:03}: {instruction}" for index, instruction in enumerate(instructions))


def format_module(module: IRModule) -> str:
    sections: list[str] = []
    for function in module.all_functions():
        params = ", ".join(function.params)
        sections.append(f"function {function.name}({params})")
        sections.append(format_instructions(function.instructions) or "  <empty>")
    return "\n\n".join(sections)
