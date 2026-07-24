"""Explainable vulnerability traces: SOURCE → FLOW → SINK."""

from __future__ import annotations

from dataclasses import dataclass, field

from analyzer.ir import Assign, BinaryOp, Call, Instruction
from analyzer.taint_engine import Vulnerability


@dataclass
class TraceStep:
    kind: str       # "SOURCE", "FLOW", or "SINK"
    variable: str
    line: int
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.kind:6}  line {self.line:>3}  {self.variable}  {self.detail}".rstrip()


@dataclass
class VulnerabilityTrace:
    vulnerability: Vulnerability
    steps: list[TraceStep] = field(default_factory=list)

    def format(self) -> str:
        header = (
            f"Vulnerability: tainted '{self.vulnerability.tainted_arg}' "
            f"reaches '{self.vulnerability.sink}' at line {self.vulnerability.line}\n"
        )
        body = "\n".join(f"  {step}" for step in self.steps)
        return header + body


class Reporter:
    """Replays IR instructions forward to reconstruct the taint propagation path."""

    def generate_trace(
        self,
        vuln: Vulnerability,
        instructions: list[Instruction],
    ) -> VulnerabilityTrace:
        trace = VulnerabilityTrace(vulnerability=vuln)
        tainted: dict[str, frozenset[str]] = {}

        for instr in instructions:
            if isinstance(instr, Call):
                if instr.function in vuln.taint_sources and instr.target is not None:
                    tainted[instr.target] = frozenset({instr.function})
                    trace.steps.append(
                        TraceStep("SOURCE", instr.target, instr.line, f"← {instr.function}()")
                    )
                elif instr.function == vuln.sink:
                    for arg in instr.args:
                        if arg in tainted or arg == vuln.tainted_arg:
                            trace.steps.append(
                                TraceStep("SINK", arg, instr.line, f"→ {instr.function}()")
                            )
                            break
                    break
                elif instr.target is not None:
                    combined = frozenset().union(*(tainted.get(a, frozenset()) for a in instr.args))
                    if combined:
                        tainted[instr.target] = combined
                        trace.steps.append(
                            TraceStep(
                                "FLOW",
                                instr.target,
                                instr.line,
                                f"← {instr.function}({', '.join(instr.args)})",
                            )
                        )

            elif isinstance(instr, Assign):
                if instr.value in tainted:
                    tainted[instr.target] = tainted[instr.value]
                    trace.steps.append(
                        TraceStep("FLOW", instr.target, instr.line, f"← {instr.value}")
                    )

            elif isinstance(instr, BinaryOp):
                left = tainted.get(instr.left, frozenset())
                right = tainted.get(instr.right, frozenset())
                combined = left | right
                if combined:
                    tainted[instr.target] = combined
                    trace.steps.append(
                        TraceStep(
                            "FLOW",
                            instr.target,
                            instr.line,
                            f"← {instr.left} {instr.operator} {instr.right}",
                        )
                    )

        return trace


def report(vuln: Vulnerability, instructions: list[Instruction]) -> VulnerabilityTrace:
    return Reporter().generate_trace(vuln, instructions)
