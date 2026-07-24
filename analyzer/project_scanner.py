"""Project-level scanner for Flask SQL injection analysis."""

from __future__ import annotations

import builtins
from dataclasses import asdict, dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from analyzer.cfg_builder import build_cfg
from analyzer.framework_profiles import FrameworkProfile, get_profile
from analyzer.interprocedural import analyze_module
from analyzer.ir import Assign, BinaryOp, BuildCollection, Call, IRFunction, IRModule, Return
from analyzer.ir_generator import generate_ir
from analyzer.parser import Parser
from analyzer.python_ast_frontend import FrontendCoverage, parse_python_ast
from analyzer.taint_engine import analyze_cfg


@dataclass
class FileAnalysis:
    path: str
    status: str
    parse_errors: int = 0
    functions: list[str] = field(default_factory=list)
    nodes_total: int = 0
    nodes_supported: int = 0
    nodes_approximated: int = 0
    nodes_ignored: int = 0
    coverage_ratio: float = 1.0
    coverage_issues: list[dict] = field(default_factory=list)
    unresolved_calls: list[str] = field(default_factory=list)
    conservative_calls: list[str] = field(default_factory=list)
    error_message: str | None = None


@dataclass
class ScanFinding:
    rule_id: str
    severity: str
    file: str
    function: str
    line: int
    sink: str
    tainted_arg: str
    sources: list[str]
    message: str


@dataclass
class ScanResult:
    profile: str
    frontend: str
    root: str
    files_total: int
    files_analyzed: int
    files_with_errors: int
    files_partial: int
    functions_analyzed: int
    nodes_total: int
    nodes_supported: int
    nodes_approximated: int
    nodes_ignored: int
    coverage_ratio: float
    unresolved_calls: int
    conservative_calls: int
    findings: list[ScanFinding] = field(default_factory=list)
    files: list[FileAnalysis] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class _FunctionContext:
    file: Path
    module_name: str
    function: IRFunction


@dataclass
class _ProjectTypes:
    variables: dict[tuple[str, str, str], str] = field(default_factory=dict)
    attributes: dict[tuple[str, str], str] = field(default_factory=dict)
    returns: dict[str, str] = field(default_factory=dict)


class ProjectScanner:
    """Scans a Flask project by combining and linking IR from Python files."""

    DEFAULT_EXCLUDE_DIRS = frozenset(
        {
            ".git",
            ".venv",
            "venv",
            "__pycache__",
            ".pytest_cache",
            "node_modules",
        }
    )

    def __init__(
        self,
        root: str | Path,
        profile: FrameworkProfile | None = None,
        exclude_dirs: set[str] | None = None,
        use_interprocedural: bool = True,
        model_parameterized_sql: bool = True,
        frontend: str = "python-ast",
    ) -> None:
        self.root = Path(root)
        self.profile = profile or get_profile("flask")
        self.use_interprocedural = use_interprocedural
        self.model_parameterized_sql = model_parameterized_sql
        self.frontend = frontend
        self.exclude_dirs = (
            set(self.DEFAULT_EXCLUDE_DIRS)
            if exclude_dirs is None
            else set(exclude_dirs)
        )

    def scan(self) -> ScanResult:
        files = self._python_files()
        file_reports: list[FileAnalysis] = []
        reports_by_file: dict[Path, FileAnalysis] = {}
        contexts: list[_FunctionContext] = []
        combined = IRModule()

        for path in files:
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                report = FileAnalysis(
                    path=self._relative(path),
                    status="READ_ERROR",
                    parse_errors=1,
                    error_message=str(exc),
                )
                file_reports.append(report)
                reports_by_file[path] = report
                continue

            program, parse_errors, coverage = self._parse_source(source, path)
            module = generate_ir(program, profile=self.profile)
            module_name = self._module_name(path)
            functions = [func.name for func in module.functions.values()]
            status = self._coverage_status(parse_errors, coverage)
            report = FileAnalysis(
                path=self._relative(path),
                status=status,
                parse_errors=parse_errors,
                functions=functions,
                nodes_total=coverage.total_nodes,
                nodes_supported=coverage.supported_nodes,
                nodes_approximated=coverage.approximated_nodes,
                nodes_ignored=coverage.ignored_nodes,
                coverage_ratio=round(coverage.coverage_ratio, 4),
                coverage_issues=[asdict(issue) for issue in coverage.issues],
            )
            file_reports.append(report)
            reports_by_file[path] = report

            if module.main.instructions:
                contexts.append(_FunctionContext(path, module_name, module.main))
            for name, function in module.functions.items():
                contexts.append(_FunctionContext(path, module_name, function))
                combined.functions[self._qualified_name(module_name, name)] = function

        known_functions = set(combined.functions)
        function_locations = {
            self._qualified_name(context.module_name, context.function.name): (
                context.file,
                context.function.name,
            )
            for context in contexts
            if context.function.name != "<main>"
        }
        call_aliases, object_types = self._project_bindings(
            contexts,
            known_functions,
        )
        project_types = self._infer_project_types(
            contexts,
            known_functions,
            call_aliases,
            object_types,
        )
        for context in contexts:
            self._link_calls(
                context,
                known_functions,
                call_aliases,
                object_types,
                project_types,
            )

        summaries = (
            analyze_module(combined, profile=self.profile)
            if self.use_interprocedural
            else {}
        )
        module_names = {context.module_name for context in contexts}
        for context in contexts:
            unresolved, conservative = self._classify_unknown_calls(
                context.function,
                summaries,
                module_names,
                known_functions,
                context.module_name,
            )
            report = reports_by_file[context.file]
            report.unresolved_calls = sorted(set(report.unresolved_calls) | unresolved)
            report.conservative_calls = sorted(
                set(report.conservative_calls) | conservative
            )

        findings: list[ScanFinding] = []
        for context in contexts:
            cfg = build_cfg(context.function.instructions, name=context.function.name)
            result = analyze_cfg(
                cfg,
                summaries=summaries,
                profile=self.profile,
                model_parameterized_sql=self.model_parameterized_sql,
            )
            for vuln in result.vulnerabilities:
                finding_file = context.file
                finding_function = context.function.name
                if vuln.sink_function in function_locations:
                    finding_file, finding_function = function_locations[vuln.sink_function]
                findings.append(
                    ScanFinding(
                        rule_id="PY.FLASK.SQLI",
                        severity="HIGH",
                        file=self._relative(finding_file),
                        function=finding_function,
                        line=vuln.line,
                        sink=vuln.sink,
                        tainted_arg=vuln.tainted_arg,
                        sources=sorted(vuln.taint_sources),
                        message=(
                            f"Tainted Flask input reaches SQL sink '{vuln.sink}' "
                            f"through '{vuln.tainted_arg}'."
                        ),
                    )
                )

        nodes_total = sum(report.nodes_total for report in file_reports)
        nodes_supported = sum(report.nodes_supported for report in file_reports)
        nodes_approximated = sum(report.nodes_approximated for report in file_reports)
        nodes_ignored = sum(report.nodes_ignored for report in file_reports)
        coverage_ratio = (
            (nodes_supported + nodes_approximated) / nodes_total
            if nodes_total
            else 1.0
        )
        return ScanResult(
            profile=self.profile.name,
            frontend=self.frontend,
            root=str(self.root),
            files_total=len(files),
            files_analyzed=sum(
                1
                for report in file_reports
                if report.status not in {"PARSE_ERROR", "READ_ERROR"}
            ),
            files_with_errors=sum(
                1
                for report in file_reports
                if report.status in {"PARSE_ERROR", "READ_ERROR"}
            ),
            files_partial=sum(1 for report in file_reports if report.status == "PARTIAL"),
            functions_analyzed=len(contexts),
            nodes_total=nodes_total,
            nodes_supported=nodes_supported,
            nodes_approximated=nodes_approximated,
            nodes_ignored=nodes_ignored,
            coverage_ratio=round(coverage_ratio, 4),
            unresolved_calls=sum(len(report.unresolved_calls) for report in file_reports),
            conservative_calls=sum(
                len(report.conservative_calls) for report in file_reports
            ),
            findings=findings,
            files=file_reports,
        )

    def _parse_source(
        self,
        source: str,
        path: Path,
    ) -> tuple[object, int, FrontendCoverage]:
        if self.frontend == "custom":
            parser = Parser.from_source(source)
            program = parser.parse()
            return program, len(parser.errors), FrontendCoverage()
        result = parse_python_ast(source, filename=str(path))
        return result.program, len(result.errors), result.coverage

    def _link_calls(
        self,
        context: _FunctionContext,
        known: set[str],
        call_aliases: dict[str, tuple[str, str]],
        object_types: dict[str, str],
        project_types: _ProjectTypes,
    ) -> None:
        for instruction in context.function.instructions:
            if not isinstance(instruction, Call):
                continue
            function, bound_receiver = self._resolve_call(
                instruction.function,
                context,
                known,
                call_aliases,
                object_types,
                project_types,
            )
            instruction.function = function
            if bound_receiver is not None:
                instruction.args.insert(0, bound_receiver)

    def _resolve_call(
        self,
        function: str,
        context: _FunctionContext,
        known: set[str],
        call_aliases: dict[str, tuple[str, str]],
        object_types: dict[str, str],
        project_types: _ProjectTypes | None = None,
    ) -> tuple[str, str | None]:
        module_name = context.module_name
        if function in known:
            return function, None
        alias = call_aliases.get(function)
        if alias is not None:
            return alias
        local_alias = call_aliases.get(self._qualified_name(module_name, function))
        if local_alias is not None:
            return local_alias
        if (
            function.startswith("self.")
            and function.count(".") == 1
            and "." in context.function.name
        ):
            class_name = context.function.name.rsplit(".", 1)[0]
            method = function.split(".", 1)[1]
            candidate = self._qualified_name(module_name, f"{class_name}.{method}")
            if candidate in known:
                return candidate, "self"
        if "." in function:
            receiver, method = function.rsplit(".", 1)
            receiver_type = (
                self._value_type(project_types, context, receiver, object_types)
                if project_types is not None
                else None
            ) or (
                object_types.get(receiver)
                or object_types.get(self._qualified_name(module_name, receiver))
            )
            if receiver_type is not None:
                candidate = f"{receiver_type}.{method}"
                if candidate in known:
                    bound_receiver = (
                        receiver
                        if receiver in object_types
                        else self._qualified_name(module_name, receiver)
                    )
                    return candidate, bound_receiver
        if function.startswith("."):
            package = module_name.rsplit(".", 1)[0] if "." in module_name else ""
            relative = function.lstrip(".")
            candidate = ".".join(part for part in (package, relative) if part)
            if candidate in known:
                return candidate, None
        local = self._qualified_name(module_name, function)
        if local in known:
            return local, None
        return function, None

    def _infer_project_types(
        self,
        contexts: list[_FunctionContext],
        known: set[str],
        call_aliases: dict[str, tuple[str, str]],
        object_types: dict[str, str],
    ) -> _ProjectTypes:
        inferred = _ProjectTypes()
        init_bindings = self._constructor_attribute_bindings(contexts)

        for _ in range(max(2, len(contexts) + 1)):
            changed = False
            for context in contexts:
                for instruction in context.function.instructions:
                    if isinstance(instruction, Call):
                        resolved, _ = self._resolve_call(
                            instruction.function,
                            context,
                            known,
                            call_aliases,
                            object_types,
                            inferred,
                        )
                        constructor = self._project_class_name(
                            instruction.function,
                            context.module_name,
                            known,
                        )
                        result_type = constructor or inferred.returns.get(resolved)
                        if instruction.target is not None and result_type is not None:
                            changed |= self._set_variable_type(
                                inferred,
                                context,
                                instruction.target,
                                result_type,
                            )
                        if constructor is not None:
                            for attribute, argument_index in init_bindings.get(
                                constructor,
                                (),
                            ):
                                if argument_index >= len(instruction.args):
                                    continue
                                argument_type = self._value_type(
                                    inferred,
                                    context,
                                    instruction.args[argument_index],
                                    object_types,
                                )
                                if argument_type is not None:
                                    changed |= self._set_attribute_type(
                                        inferred,
                                        constructor,
                                        attribute,
                                        argument_type,
                                    )
                        continue

                    if isinstance(instruction, BinaryOp):
                        if instruction.operator not in {"or", "and"}:
                            continue
                        value_type = self._merged_value_type(
                            inferred,
                            context,
                            (instruction.left, instruction.right),
                            object_types,
                        )
                        if value_type is not None:
                            changed |= self._set_variable_type(
                                inferred,
                                context,
                                instruction.target,
                                value_type,
                            )
                        continue

                    if isinstance(instruction, BuildCollection):
                        if instruction.kind != "conditional":
                            continue
                        value_type = self._merged_value_type(
                            inferred,
                            context,
                            instruction.elements,
                            object_types,
                        )
                        if value_type is not None:
                            changed |= self._set_variable_type(
                                inferred,
                                context,
                                instruction.target,
                                value_type,
                            )
                        continue

                    if isinstance(instruction, Assign):
                        value_type = self._value_type(
                            inferred,
                            context,
                            instruction.value,
                            object_types,
                        )
                        if value_type is None:
                            continue
                        if instruction.target.startswith("self."):
                            class_name = self._context_class(context)
                            attribute = instruction.target.split(".", 1)[1]
                            if class_name is not None and "." not in attribute:
                                changed |= self._set_attribute_type(
                                    inferred,
                                    class_name,
                                    attribute,
                                    value_type,
                                )
                        else:
                            changed |= self._set_variable_type(
                                inferred,
                                context,
                                instruction.target,
                                value_type,
                            )
                        continue

                    if isinstance(instruction, Return) and instruction.value is not None:
                        value_type = self._value_type(
                            inferred,
                            context,
                            instruction.value,
                            object_types,
                        )
                        function_name = self._context_function(context)
                        if value_type is not None and function_name is not None:
                            if inferred.returns.get(function_name) is None:
                                inferred.returns[function_name] = value_type
                                changed = True
            if not changed:
                break

        return inferred

    def _constructor_attribute_bindings(
        self,
        contexts: list[_FunctionContext],
    ) -> dict[str, list[tuple[str, int]]]:
        bindings: dict[str, list[tuple[str, int]]] = {}
        for context in contexts:
            if not context.function.name.endswith(".__init__"):
                continue
            class_name = self._context_class(context)
            if class_name is None:
                continue
            params = context.function.params
            for instruction in context.function.instructions:
                if not isinstance(instruction, Assign):
                    continue
                if not instruction.target.startswith("self."):
                    continue
                if instruction.value not in params:
                    continue
                parameter_index = params.index(instruction.value)
                if parameter_index == 0:
                    continue
                attribute = instruction.target.split(".", 1)[1]
                if "." in attribute:
                    continue
                bindings.setdefault(class_name, []).append(
                    (attribute, parameter_index - 1)
                )
        return bindings

    def _value_type(
        self,
        inferred: _ProjectTypes | None,
        context: _FunctionContext,
        value: str,
        object_types: dict[str, str],
    ) -> str | None:
        if inferred is None:
            return None
        variable = inferred.variables.get(self._variable_key(context, value))
        if variable is not None:
            return variable
        global_type = (
            object_types.get(value)
            or object_types.get(self._qualified_name(context.module_name, value))
        )
        if global_type is not None:
            return global_type
        if value.startswith("self."):
            class_name = self._context_class(context)
            attribute = value.split(".", 1)[1]
            if class_name is not None and "." not in attribute:
                return inferred.attributes.get((class_name, attribute))
        return None

    def _merged_value_type(
        self,
        inferred: _ProjectTypes,
        context: _FunctionContext,
        values: object,
        object_types: dict[str, str],
    ) -> str | None:
        candidates = {
            value_type
            for value in values
            if (
                value_type := self._value_type(
                    inferred,
                    context,
                    value,
                    object_types,
                )
            )
            is not None
        }
        return next(iter(candidates)) if len(candidates) == 1 else None

    def _set_variable_type(
        self,
        inferred: _ProjectTypes,
        context: _FunctionContext,
        variable: str,
        value_type: str,
    ) -> bool:
        key = self._variable_key(context, variable)
        existing = inferred.variables.get(key)
        if existing is not None:
            return False
        inferred.variables[key] = value_type
        return True

    @staticmethod
    def _set_attribute_type(
        inferred: _ProjectTypes,
        class_name: str,
        attribute: str,
        value_type: str,
    ) -> bool:
        key = (class_name, attribute)
        existing = inferred.attributes.get(key)
        if existing is not None:
            return False
        inferred.attributes[key] = value_type
        return True

    def _variable_key(
        self,
        context: _FunctionContext,
        variable: str,
    ) -> tuple[str, str, str]:
        return (context.module_name, context.function.name, variable)

    def _context_class(self, context: _FunctionContext) -> str | None:
        if context.function.name == "<main>" or "." not in context.function.name:
            return None
        class_name = context.function.name.rsplit(".", 1)[0]
        return self._qualified_name(context.module_name, class_name)

    def _context_function(self, context: _FunctionContext) -> str | None:
        if context.function.name == "<main>":
            return None
        return self._qualified_name(context.module_name, context.function.name)

    def _project_bindings(
        self,
        contexts: list[_FunctionContext],
        known: set[str],
    ) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
        call_aliases: dict[str, tuple[str, str]] = {}
        object_types: dict[str, str] = {}

        for context in contexts:
            if context.function.name != "<main>":
                continue
            local_types: dict[str, str] = {}
            for instruction in context.function.instructions:
                if isinstance(instruction, Call) and instruction.target is not None:
                    class_name = self._project_class_name(
                        instruction.function,
                        context.module_name,
                        known,
                    )
                    if class_name is not None:
                        local_types[instruction.target] = class_name
                    continue
                if not isinstance(instruction, Assign):
                    continue

                value_type = local_types.get(instruction.value)
                qualified_target = self._qualified_name(
                    context.module_name,
                    instruction.target,
                )
                if value_type is not None:
                    local_types[instruction.target] = value_type
                    object_types[qualified_target] = value_type
                    continue

                if "." not in instruction.value:
                    continue
                receiver, method = instruction.value.rsplit(".", 1)
                receiver_type = local_types.get(receiver)
                if receiver_type is None:
                    continue
                candidate = f"{receiver_type}.{method}"
                if candidate in known:
                    qualified_receiver = self._qualified_name(
                        context.module_name,
                        receiver,
                    )
                    call_aliases[qualified_target] = (
                        candidate,
                        qualified_receiver,
                    )

        return call_aliases, object_types

    def _project_class_name(
        self,
        function: str,
        module_name: str,
        known: set[str],
    ) -> str | None:
        candidates = (function, self._qualified_name(module_name, function))
        for candidate in candidates:
            prefix = f"{candidate}."
            if any(name.startswith(prefix) for name in known):
                return candidate
        return None

    def _classify_unknown_calls(
        self,
        function: IRFunction,
        summaries: dict,
        module_names: set[str],
        known_functions: set[str],
        module_name: str,
    ) -> tuple[set[str], set[str]]:
        unresolved: set[str] = set()
        conservative: set[str] = set()
        synthetic_runtime = {
            "iter",
            "has_next",
            "next",
            "str.format",
            "sqlalchemy.text",
        }
        for instruction in function.instructions:
            if not isinstance(instruction, Call):
                continue
            name = instruction.function
            if (
                self.profile.is_source(name)
                or self.profile.is_sink(name)
                or self.profile.is_sanitizer(name)
                or name in summaries
                or name in synthetic_runtime
                or self.profile.call_return_kind(name) is not None
                or instruction.return_kind is not None
                or self._is_builtin_call(name)
                or self._project_class_name(
                    name,
                    module_name,
                    known_functions,
                )
                is not None
            ):
                continue
            if self._is_external_conservative_call(name):
                conservative.add(name)
                continue
            if self._looks_project_local(name, module_names):
                unresolved.add(name)
            else:
                conservative.add(name)
        return unresolved, conservative

    @staticmethod
    def _is_builtin_call(name: str) -> bool:
        return "." not in name and hasattr(builtins, name)

    @staticmethod
    def _is_external_conservative_call(name: str) -> bool:
        protocol_methods = {
            "append",
            "extend",
        }
        method = name.rsplit(".", 1)[-1]
        if method in protocol_methods:
            return True

        external_patterns = (
            "*.db.init_app",
            "*.migrate.init_app",
            "*.db.session.*",
            "*.query.*",
        )
        if any(fnmatchcase(name, pattern) for pattern in external_patterns):
            return True

        final_component = name.rsplit(".", 1)[-1]
        return final_component.endswith("Model")

    @staticmethod
    def _looks_project_local(name: str, module_names: set[str]) -> bool:
        if name.startswith("self."):
            return True
        if "." not in name:
            return True
        return any(
            "." in module
            and (name == module or name.startswith(f"{module}."))
            for module in module_names
        )

    def _python_files(self) -> list[Path]:
        if self.root.is_file():
            return [self.root] if self.root.suffix == ".py" else []
        files: list[Path] = []
        for path in sorted(self.root.rglob("*.py")):
            if any(part in self.exclude_dirs for part in path.parts):
                continue
            files.append(path)
        return files

    def _module_name(self, path: Path) -> str:
        rel = Path(self._relative(path)).with_suffix("")
        parts = list(rel.parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts) or path.stem

    @staticmethod
    def _qualified_name(module_name: str, function: str) -> str:
        return f"{module_name}.{function}" if module_name else function

    @staticmethod
    def _coverage_status(parse_errors: int, coverage: FrontendCoverage) -> str:
        if parse_errors:
            return "PARSE_ERROR"
        if coverage.ignored_nodes:
            return "PARTIAL"
        if coverage.approximated_nodes:
            return "APPROXIMATED"
        return "OK"

    def _relative(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root if self.root.is_dir() else self.root.parent))
        except ValueError:
            return str(path)
