"""Interprocedural taint analysis via per-function summaries."""

from __future__ import annotations

from dataclasses import dataclass, field

from analyzer.framework_profiles import FrameworkProfile, get_profile
from analyzer.ir import Assign, BinaryOp, BuildCollection, BuildFString, Call, IRFunction, IRModule, Return, Subscript

TaintState = dict[str, frozenset[str]]


@dataclass
class FunctionSummary:
    """Describes how a function affects taint flow."""

    name: str
    # True when the function itself calls a taint source and returns the result
    returns_tainted: bool = False
    # True when a tainted argument flows through and is returned
    taints_arguments: bool = False
    # True when the function sanitizes its input before returning
    returns_sanitized: bool = False
    taint_sources: frozenset[str] = field(default_factory=frozenset)


class InterproceduralAnalyzer:
    """Builds taint summaries for every function in an IRModule.

    Uses two linear-scan passes per function:
      Pass 1 — empty initial state: detects functions that are intrinsic sources.
      Pass 2 — parameters pre-tainted: detects pass-through and sanitization.
    """

    def __init__(self, profile: FrameworkProfile | None = None) -> None:
        self.profile = profile or get_profile("base")
        self.sources = self.profile.sources
        self.sanitizers = self.profile.sanitizers

    def analyze(self, module: IRModule) -> dict[str, FunctionSummary]:
        return {
            name: self._summarize(name, func)
            for name, func in module.functions.items()
        }

    def _summarize(self, name: str, func: IRFunction) -> FunctionSummary:
        summary = FunctionSummary(name=name)

        # --- Pass 1: no initial taint ---
        state: TaintState = {}
        for instr in func.instructions:
            self._apply(instr, state)
            if isinstance(instr, Return) and instr.value:
                taint = state.get(instr.value, frozenset())
                if taint:
                    summary.returns_tainted = True
                    summary.taint_sources = taint

        # --- Pass 2: all params pre-tainted ---
        state_p: TaintState = {p: frozenset({f"param:{p}"}) for p in func.params}
        has_sanitizer = False
        return_tainted_p = False
        for instr in func.instructions:
            if isinstance(instr, Call) and instr.function in self.sanitizers:
                if instr.target is not None:
                    state_p.pop(instr.target, None)
                has_sanitizer = True
            else:
                self._apply(instr, state_p)
            if isinstance(instr, Return) and instr.value:
                if state_p.get(instr.value, frozenset()):
                    return_tainted_p = True

        if return_tainted_p:
            summary.taints_arguments = True
        if has_sanitizer and not return_tainted_p and func.params:
            summary.returns_sanitized = True

        return summary

    def _apply(self, instr: object, state: TaintState) -> None:
        """Apply one IR instruction to a taint state in-place."""
        if isinstance(instr, Call):
            if instr.function in self.sources and instr.target is not None:
                state[instr.target] = frozenset({instr.function})
            elif instr.target is not None:
                combined = self._call_input_taint(instr, state)
                if combined:
                    state[instr.target] = combined
                else:
                    state.pop(instr.target, None)
        elif isinstance(instr, Assign):
            taint = state.get(instr.value, frozenset())
            if taint:
                state[instr.target] = taint
            else:
                state.pop(instr.target, None)
        elif isinstance(instr, BinaryOp):
            combined = state.get(instr.left, frozenset()) | state.get(instr.right, frozenset())
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)
        elif isinstance(instr, BuildCollection):
            combined = frozenset().union(
                *(state.get(element, frozenset()) for element in instr.elements)
            )
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)
        elif isinstance(instr, BuildFString):
            combined = frozenset().union(
                *(state.get(field, frozenset()) for field in instr.fields)
            )
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)
        elif isinstance(instr, Subscript):
            combined = state.get(instr.collection, frozenset()) | state.get(instr.index, frozenset())
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)

    def _call_input_taint(self, instr: Call, state: TaintState) -> frozenset[str]:
        receiver = instr.function.rsplit(".", 1)[0] if "." in instr.function else ""
        return frozenset().union(
            state.get(receiver, frozenset()),
            *(state.get(arg, frozenset()) for arg in instr.args),
        )


def analyze_module(
    module: IRModule,
    profile: FrameworkProfile | None = None,
) -> dict[str, FunctionSummary]:
    return InterproceduralAnalyzer(profile=profile).analyze(module)
