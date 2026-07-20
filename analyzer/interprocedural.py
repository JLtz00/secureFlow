"""Interprocedural taint analysis via per-function summaries."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

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
    tainted_arguments_reach_sink: bool = False
    sink: str | None = None
    sink_line: int | None = None
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
        self.summaries: dict[str, FunctionSummary] = {}

    def analyze(self, module: IRModule) -> dict[str, FunctionSummary]:
        self.summaries = {
            name: FunctionSummary(name=name)
            for name in module.functions
        }
        for _ in range(max(1, len(module.functions) + 1)):
            updated = {
                name: self._summarize(name, func)
                for name, func in module.functions.items()
            }
            if updated == self.summaries:
                break
            self.summaries = updated
        return self.summaries

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
            if isinstance(instr, Call):
                sink = self._tainted_sink(instr, state_p)
                if sink is not None:
                    summary.tainted_arguments_reach_sink = True
                    summary.sink = sink
                    summary.sink_line = instr.line
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
            elif instr.function in self.summaries and instr.target is not None:
                self._apply_summary(instr, state, self.summaries[instr.function])
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

    def _tainted_sink(self, instr: Call, state: TaintState) -> str | None:
        if instr.function in self.profile.sinks:
            if self._is_parameterized_sink(instr, state):
                return None
            if any(state.get(arg, frozenset()) for arg in instr.args):
                return instr.function
        summary = self.summaries.get(instr.function)
        if summary is not None and summary.tainted_arguments_reach_sink:
            if self._call_input_taint(instr, state):
                return summary.sink or instr.function
        return None

    def _is_parameterized_sink(self, instr: Call, state: TaintState) -> bool:
        if len(instr.args) < 2:
            return False
        query_arg = instr.args[0]
        if state.get(query_arg, frozenset()):
            return False
        query_text = self._literal_string_value(query_arg)
        if query_text is None:
            return False
        return "?" in query_text or "%s" in query_text or re.search(r":\w+", query_text) is not None

    def _literal_string_value(self, value: str) -> str | None:
        raw = value.strip()
        prefix_pattern = r"(?i)^(?:r|u|b|br|rb|f|fr|rf)?"
        if not re.match(prefix_pattern + r"(['\"])", raw):
            return None
        quote_index = 0
        while quote_index < len(raw) and raw[quote_index].lower() in "rubf":
            quote_index += 1
        if quote_index >= len(raw) or raw[quote_index] not in {"'", '"'}:
            return None
        quote = raw[quote_index]
        if len(raw) < quote_index + 2 or raw[-1] != quote:
            return None
        return raw[quote_index + 1:-1]

    def _apply_summary(
        self,
        instr: Call,
        state: TaintState,
        summary: FunctionSummary,
    ) -> None:
        if instr.target is None:
            return
        if summary.returns_sanitized:
            state.pop(instr.target, None)
            return
        if summary.returns_tainted:
            state[instr.target] = summary.taint_sources or frozenset({summary.name})
            return
        if summary.taints_arguments:
            combined = self._call_input_taint(instr, state)
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)
            return
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
