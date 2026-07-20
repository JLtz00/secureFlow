"""Project-level scanner for Flask SQL injection analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from analyzer.cfg_builder import build_cfg
from analyzer.framework_profiles import FrameworkProfile, get_profile
from analyzer.interprocedural import analyze_module
from analyzer.ir import IRFunction, IRModule
from analyzer.ir_generator import generate_ir
from analyzer.parser import Parser
from analyzer.taint_engine import analyze_cfg


@dataclass
class FileAnalysis:
    path: str
    status: str
    parse_errors: int = 0
    functions: list[str] = field(default_factory=list)


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
    root: str
    files_total: int
    files_analyzed: int
    files_with_errors: int
    functions_analyzed: int
    findings: list[ScanFinding] = field(default_factory=list)
    files: list[FileAnalysis] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class _FunctionContext:
    file: Path
    module_name: str
    function: IRFunction


class ProjectScanner:
    """Scans a Flask project by combining IR from all Python files."""

    def __init__(
        self,
        root: str | Path,
        profile: FrameworkProfile | None = None,
        exclude_dirs: set[str] | None = None,
        use_interprocedural: bool = True,
        model_parameterized_sql: bool = True,
    ) -> None:
        self.root = Path(root)
        self.profile = profile or get_profile("flask")
        self.use_interprocedural = use_interprocedural
        self.model_parameterized_sql = model_parameterized_sql
        self.exclude_dirs = exclude_dirs or {
            ".git",
            ".venv",
            "venv",
            "__pycache__",
            ".pytest_cache",
            "node_modules",
        }

    def scan(self) -> ScanResult:
        files = self._python_files()
        file_reports: list[FileAnalysis] = []
        contexts: list[_FunctionContext] = []
        combined = IRModule()

        for path in files:
            source = path.read_text()
            parser = Parser.from_source(source)
            program = parser.parse()
            module = generate_ir(program)
            module_name = self._module_name(path)

            functions = [func.name for func in module.functions.values()]
            status = "OK" if not parser.errors else "PARSE_ERROR"
            file_reports.append(
                FileAnalysis(
                    path=self._relative(path),
                    status=status,
                    parse_errors=len(parser.errors),
                    functions=functions,
                )
            )

            if module.main.instructions:
                contexts.append(_FunctionContext(path, module_name, module.main))
            for name, function in module.functions.items():
                contexts.append(_FunctionContext(path, module_name, function))
                combined.functions.setdefault(name, function)
                combined.functions[f"{module_name}.{name}"] = function

        summaries = analyze_module(combined, profile=self.profile) if self.use_interprocedural else {}
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
                findings.append(
                    ScanFinding(
                        rule_id="PY.FLASK.SQLI",
                        severity="HIGH",
                        file=self._relative(context.file),
                        function=context.function.name,
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

        return ScanResult(
            profile=self.profile.name,
            root=str(self.root),
            files_total=len(files),
            files_analyzed=sum(1 for f in file_reports if f.status == "OK"),
            files_with_errors=sum(1 for f in file_reports if f.status != "OK"),
            functions_analyzed=len(contexts),
            findings=findings,
            files=file_reports,
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
        return ".".join(rel.parts)

    def _relative(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root if self.root.is_dir() else self.root.parent))
        except ValueError:
            return str(path)
