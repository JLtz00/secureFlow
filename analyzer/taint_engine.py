"""Forward dataflow taint analysis using the Worklist algorithm.

Tracks untrusted data (sources) through assignments, binary ops, branches,
and loops until it reaches a dangerous function call (sink), reporting
SQL injection vulnerabilities.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import re

from analyzer.cfg_builder import CFG, BasicBlock
from analyzer.framework_profiles import FrameworkProfile, get_profile
from analyzer.interprocedural import FunctionSummary
from analyzer.ir import Assign, BinaryOp, BuildCollection, BuildFString, Call, Subscript

# Maps variable names to the set of taint sources that contaminate them.
# A variable absent from the dict (or mapped to empty frozenset) is clean.
TaintState = dict[str, frozenset[str]]


@dataclass
class Vulnerability:
    """A tainted argument flowing into a SQL sink."""

    sink: str
    tainted_arg: str
    taint_sources: frozenset[str]
    line: int
    block_id: int

    def __str__(self) -> str:
        sources = ", ".join(sorted(self.taint_sources))
        return (
            f"[VULN] Tainted data reaches sink '{self.sink}' "
            f"via '{self.tainted_arg}' (sources: {sources}) at line {self.line}"
        )


@dataclass
class TaintResult:
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    # Final OUT state for each basic block after fixpoint
    block_out: dict[int, TaintState] = field(default_factory=dict)

    @property
    def is_vulnerable(self) -> bool:
        return bool(self.vulnerabilities)


class TaintEngine:
    """Worklist-based forward dataflow taint analysis over a CFG.

    Algorithm:
      1. Initialize IN/OUT for every block to empty taint state.
      2. Seed the worklist with all blocks so each is processed at least once.
      3. For each block B dequeued:
           IN[B]  = join(OUT[pred] for pred in predecessors(B))
           OUT[B] = transfer(B, IN[B])
         If OUT[B] changed, re-enqueue all successors of B.
      4. Repeat until the worklist is empty (fixpoint reached).
    """

    def __init__(
        self,
        summaries: dict[str, FunctionSummary] | None = None,
        profile: FrameworkProfile | None = None,
    ) -> None:
        self.summaries = summaries or {}
        self.profile = profile or get_profile("base")
        self.sources = self.profile.sources
        self.sinks = self.profile.sinks
        self.sanitizers = self.profile.sanitizers

    def analyze(self, cfg: CFG) -> TaintResult:
        result = TaintResult()
        if not cfg.blocks or cfg.entry is None:
            return result

        in_state: dict[int, TaintState] = {b.id: {} for b in cfg.blocks}
        out_state: dict[int, TaintState] = {b.id: {} for b in cfg.blocks}
        # Deduplicate vulnerabilities: (sink, arg, line) uniquely identifies one report
        reported: set[tuple[str, str, int]] = set()

        # Seed with all blocks so each is processed at least once
        worklist: deque[int] = deque(b.id for b in cfg.blocks)

        while worklist:
            block_id = worklist.popleft()
            block = self._block_by_id(cfg, block_id)
            if block is None:
                continue

            # IN[B] = join of OUT[pred] for every predecessor of B
            preds = [e.source for e in cfg.edges if e.target == block_id]
            merged: TaintState = {}
            for pred_id in preds:
                merged = self._join(merged, out_state[pred_id])
            in_state[block_id] = merged

            # OUT[B] = transfer(IN[B], B)
            new_out, vulns = self._transfer(block, dict(merged))

            for v in vulns:
                key = (v.sink, v.tainted_arg, v.line)
                if key not in reported:
                    reported.add(key)
                    result.vulnerabilities.append(v)

            # Propagate changes to successors
            if new_out != out_state[block_id]:
                out_state[block_id] = new_out
                for e in cfg.edges:
                    if e.source == block_id:
                        worklist.append(e.target)

        result.block_out = out_state
        return result

    # ------------------------------------------------------------------ helpers

    def _block_by_id(self, cfg: CFG, block_id: int) -> BasicBlock | None:
        for b in cfg.blocks:
            if b.id == block_id:
                return b
        return None

    def _join(self, a: TaintState, b: TaintState) -> TaintState:
        """Union join: a variable is tainted if tainted in either predecessor."""
        merged = dict(a)
        for var, sources in b.items():
            merged[var] = merged.get(var, frozenset()) | sources
        return merged

    # ---------------------------------------------------------------- transfer

    def _transfer(
        self, block: BasicBlock, state: TaintState
    ) -> tuple[TaintState, list[Vulnerability]]:
        """Apply each IR instruction in block to the taint state.

        Returns the updated state and any vulnerabilities detected.
        """
        vulns: list[Vulnerability] = []
        parameterized_templates: set[str] = set()

        for instr in block.instructions:
            if isinstance(instr, Assign):
                # target = value  →  propagate taint from value variable
                taint = state.get(instr.value, frozenset())
                if instr.value in parameterized_templates:
                    parameterized_templates.add(instr.target)
                else:
                    parameterized_templates.discard(instr.target)
                if taint:
                    state[instr.target] = taint
                else:
                    state.pop(instr.target, None)

            elif isinstance(instr, BinaryOp):
                parameterized_templates.discard(instr.target)
                # target = left OP right  →  union of operand taints
                left_taint = state.get(instr.left, frozenset())
                right_taint = state.get(instr.right, frozenset())
                combined = left_taint | right_taint
                if combined:
                    state[instr.target] = combined
                else:
                    state.pop(instr.target, None)

            elif isinstance(instr, BuildCollection):
                parameterized_templates.discard(instr.target)
                combined = frozenset().union(
                    *(state.get(element, frozenset()) for element in instr.elements)
                )
                if combined:
                    state[instr.target] = combined
                else:
                    state.pop(instr.target, None)

            elif isinstance(instr, BuildFString):
                parameterized_templates.discard(instr.target)
                combined = frozenset().union(
                    *(state.get(field, frozenset()) for field in instr.fields)
                )
                if combined:
                    state[instr.target] = combined
                else:
                    state.pop(instr.target, None)

            elif isinstance(instr, Subscript):
                parameterized_templates.discard(instr.target)
                combined = state.get(instr.collection, frozenset()) | state.get(instr.index, frozenset())
                if combined:
                    state[instr.target] = combined
                else:
                    state.pop(instr.target, None)

            elif isinstance(instr, Call):
                self._handle_call(instr, state, vulns, block.id, parameterized_templates)

        return state, vulns

    def _handle_call(
        self,
        instr: Call,
        state: TaintState,
        vulns: list[Vulnerability],
        block_id: int,
        parameterized_templates: set[str],
    ) -> None:
        fn = instr.function
        if instr.target is not None:
            parameterized_templates.discard(instr.target)

        if fn in self.sources:
            # Return value of a source is always tainted
            if instr.target is not None:
                state[instr.target] = frozenset({fn})

        elif fn in self.sanitizers:
            # Sanitizers produce clean output regardless of arguments
            if instr.target is not None:
                state.pop(instr.target, None)

        elif fn in self.sinks:
            if self._is_safe_parameterized_sql_call(instr, state, parameterized_templates):
                return

            # Check every argument: tainted data reaching a sink is a vulnerability
            for arg in instr.args:
                arg_taint = state.get(arg, frozenset())
                if arg_taint:
                    vulns.append(
                        Vulnerability(
                            sink=fn,
                            tainted_arg=arg,
                            taint_sources=arg_taint,
                            line=instr.line,
                            block_id=block_id,
                        )
                    )

        elif fn in self.summaries:
            self._apply_function_summary(
                instr,
                state,
                self.summaries[fn],
                vulns,
                block_id,
            )

        elif fn == "sqlalchemy.text":
            if instr.target is not None:
                self._mark_sqlalchemy_text(instr, state, parameterized_templates)

        else:
            # Conservative assumption: if any argument is tainted, so is the return value
            if instr.target is not None:
                combined = self._call_input_taint(instr, state)
                if combined:
                    state[instr.target] = combined
                else:
                    state.pop(instr.target, None)

    def _apply_function_summary(
        self,
        instr: Call,
        state: TaintState,
        summary: FunctionSummary,
        vulns: list[Vulnerability],
        block_id: int,
    ) -> None:
        combined = self._call_input_taint(instr, state)
        if summary.tainted_arguments_reach_sink and combined:
            vulns.append(
                Vulnerability(
                    sink=summary.sink or instr.function,
                    tainted_arg=instr.args[0] if instr.args else instr.function,
                    taint_sources=combined,
                    line=instr.line,
                    block_id=block_id,
                )
            )

        if instr.target is None:
            return

        if summary.returns_sanitized:
            state.pop(instr.target, None)
            return

        if summary.returns_tainted:
            state[instr.target] = summary.taint_sources or frozenset({summary.name})
            return

        if summary.taints_arguments:
            if combined:
                state[instr.target] = combined
            else:
                state.pop(instr.target, None)
            return

        state.pop(instr.target, None)

    def _mark_sqlalchemy_text(
        self,
        instr: Call,
        state: TaintState,
        parameterized_templates: set[str],
    ) -> None:
        if instr.target is None:
            return

        query_text = self._literal_string_value(instr.args[0]) if instr.args else None
        if query_text is not None and self._has_sql_placeholder(query_text):
            parameterized_templates.add(instr.target)

        combined = frozenset().union(*(state.get(arg, frozenset()) for arg in instr.args))
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

    def _is_safe_parameterized_sql_call(
        self,
        instr: Call,
        state: TaintState,
        parameterized_templates: set[str],
    ) -> bool:
        if len(instr.args) < 2:
            return False

        query_arg = instr.args[0]
        if state.get(query_arg, frozenset()):
            return False

        if query_arg in parameterized_templates:
            return True

        query_text = self._literal_string_value(query_arg)
        if query_text is None:
            return False

        return self._has_sql_placeholder(query_text)

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

    def _has_sql_placeholder(self, query: str) -> bool:
        return (
            "?" in query
            or "%s" in query
            or re.search(r":\w+", query) is not None
        )


def analyze_cfg(
    cfg: CFG,
    summaries: dict[str, FunctionSummary] | None = None,
    profile: FrameworkProfile | None = None,
) -> TaintResult:
    return TaintEngine(summaries=summaries, profile=profile).analyze(cfg)
