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
    sink_function: str | None = None
    taint_sources: frozenset[str] = field(default_factory=frozenset)
    return_tainted_params: frozenset[int] = field(default_factory=frozenset)
    sink_tainted_params: frozenset[int] = field(default_factory=frozenset)
    sanitized_return_params: frozenset[int] = field(default_factory=frozenset)


class InterproceduralAnalyzer:
    """Builds taint summaries for every function in an IRModule.

    Uses two linear-scan passes per function:
      Pass 1 — empty initial state: detects functions that are intrinsic sources.
      Pass 2 — parameters pre-tainted: detects pass-through and sanitization.
    """

    def __init__(self, profile: FrameworkProfile | None = None) -> None:
        self.profile = profile or get_profile("base")
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
                taint = self._lookup_taint(state, instr.value)
                if taint:
                    summary.returns_tainted = True
                    summary.taint_sources = taint

        return_params: set[int] = set()
        sink_params: set[int] = set()
        sanitized_params: set[int] = set()

        # Analyze each parameter independently so wrappers with multiple
        # arguments do not contaminate unrelated call-site values.
        for index, param in enumerate(func.params):
            state_p: TaintState = {param: frozenset({f"param:{param}"})}
            parameterized_templates: set[str] = set()
            sanitizer_seen_for_param = False
            return_tainted = False
            for instr in func.instructions:
                if isinstance(instr, Call) and self.profile.is_sanitizer(instr.function):
                    if self._call_input_taint(instr, state_p):
                        sanitizer_seen_for_param = True
                self._update_parameterized_templates(instr, parameterized_templates)
                self._apply(instr, state_p)
                if isinstance(instr, Call):
                    sink = self._tainted_sink(instr, state_p, parameterized_templates)
                    if sink is not None:
                        sink_params.add(index)
                        summary.sink = sink
                        nested = self.summaries.get(instr.function)
                        if nested is not None and nested.tainted_arguments_reach_sink:
                            summary.sink_line = nested.sink_line or instr.line
                            summary.sink_function = nested.sink_function or instr.function
                        else:
                            summary.sink_line = instr.line
                            summary.sink_function = name
                if isinstance(instr, Return) and instr.value:
                    if self._lookup_taint(state_p, instr.value):
                        return_tainted = True
            if return_tainted:
                return_params.add(index)
            elif sanitizer_seen_for_param:
                sanitized_params.add(index)

        summary.return_tainted_params = frozenset(return_params)
        summary.sink_tainted_params = frozenset(sink_params)
        summary.sanitized_return_params = frozenset(sanitized_params)
        summary.taints_arguments = bool(return_params)
        summary.tainted_arguments_reach_sink = bool(sink_params)
        summary.returns_sanitized = bool(sanitized_params) and not return_params

        return summary

    def _apply(self, instr: object, state: TaintState) -> None:
        """Apply one IR instruction to a taint state in-place."""
        if isinstance(instr, Call):
            if self.profile.is_source(instr.function) and instr.target is not None:
                state[instr.target] = frozenset({instr.function})
            elif self.profile.is_sanitizer(instr.function) and instr.target is not None:
                state.pop(instr.target, None)
            elif instr.function in self.summaries and instr.target is not None:
                self._apply_summary(instr, state, self.summaries[instr.function])
            elif instr.target is not None:
                combined = self._call_input_taint(instr, state)
                if combined:
                    state[instr.target] = combined
                else:
                    state.pop(instr.target, None)
        elif isinstance(instr, Assign):
            taint = self._lookup_taint(state, instr.value)
            if taint:
                state[instr.target] = taint
            else:
                state.pop(instr.target, None)
        elif isinstance(instr, BinaryOp):
            combined = self._lookup_taint(state, instr.left) | self._lookup_taint(
                state, instr.right
            )
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)
        elif isinstance(instr, BuildCollection):
            combined = frozenset().union(
                *(self._lookup_taint(state, element) for element in instr.elements)
            )
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)
        elif isinstance(instr, BuildFString):
            combined = frozenset().union(
                *(self._lookup_taint(state, field) for field in instr.fields)
            )
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)
        elif isinstance(instr, Subscript):
            combined = (
                self._lookup_taint(state, instr.access_path or "")
                | self._lookup_taint(state, instr.collection)
                | self._lookup_taint(state, instr.index)
            )
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)

    def _tainted_sink(
        self,
        instr: Call,
        state: TaintState,
        parameterized_templates: set[str],
    ) -> str | None:
        if self.profile.is_sink(instr.function):
            if self._is_parameterized_sink(instr, state, parameterized_templates):
                return None
            if any(self._lookup_taint(state, arg) for arg in instr.args):
                return instr.function
        summary = self.summaries.get(instr.function)
        if summary is not None and summary.tainted_arguments_reach_sink:
            if self._summary_input_taint(instr, state, summary.sink_tainted_params):
                return summary.sink or instr.function
        return None

    def _is_parameterized_sink(
        self,
        instr: Call,
        state: TaintState,
        parameterized_templates: set[str],
    ) -> bool:
        if len(instr.args) < 2:
            return False
        query_arg = instr.args[0]
        if self._lookup_taint(state, query_arg):
            return False
        if query_arg in parameterized_templates:
            return True
        query_text = self._literal_string_value(query_arg)
        if query_text is None:
            return False
        return (
            "?" in query_text
            or "%s" in query_text
            or re.search(r"%\([^)]+\)s", query_text) is not None
            or re.search(r":\w+", query_text) is not None
        )

    def _update_parameterized_templates(
        self,
        instr: object,
        templates: set[str],
    ) -> None:
        if isinstance(instr, Assign):
            if instr.value in templates:
                templates.add(instr.target)
            else:
                templates.discard(instr.target)
            return
        if not isinstance(instr, Call) or instr.target is None:
            return
        templates.discard(instr.target)
        if instr.function != "sqlalchemy.text" or not instr.args:
            return
        query = self._literal_string_value(instr.args[0])
        if query is not None and (
            "?" in query
            or "%s" in query
            or re.search(r"%\([^)]+\)s", query) is not None
            or re.search(r":\w+", query) is not None
        ):
            templates.add(instr.target)

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
        combined = self._summary_input_taint(
            instr,
            state,
            summary.return_tainted_params,
        )
        if summary.returns_tainted:
            combined |= summary.taint_sources or frozenset({summary.name})
        if combined:
            state[instr.target] = combined
        else:
            state.pop(instr.target, None)

    def _call_input_taint(self, instr: Call, state: TaintState) -> frozenset[str]:
        receiver = instr.function.rsplit(".", 1)[0] if "." in instr.function else ""
        return frozenset().union(
            self._lookup_taint(state, receiver),
            *(self._lookup_taint(state, arg) for arg in instr.args),
        )

    def _summary_input_taint(
        self,
        instr: Call,
        state: TaintState,
        parameter_indexes: frozenset[int],
    ) -> frozenset[str]:
        return frozenset().union(
            *(
                self._lookup_taint(state, instr.args[index])
                for index in parameter_indexes
                if index < len(instr.args)
            )
        )

    def _lookup_taint(self, state: TaintState, value: str) -> frozenset[str]:
        current = value
        while current:
            taint = state.get(current, frozenset())
            if taint:
                return taint
            if current.endswith("]") and "[" in current:
                current = current.rsplit("[", 1)[0]
            elif "." in current:
                current = current.rsplit(".", 1)[0]
            else:
                break
        return frozenset()


def analyze_module(
    module: IRModule,
    profile: FrameworkProfile | None = None,
) -> dict[str, FunctionSummary]:
    return InterproceduralAnalyzer(profile=profile).analyze(module)
