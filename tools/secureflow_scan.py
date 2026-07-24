"""Command-line scanner for SecureFlow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from analyzer.framework_profiles import get_profile, load_profile
from analyzer.project_scanner import ProjectScanner, ScanFinding, ScanResult


def _text_report(result: ScanResult) -> str:
    lines = [
        "SecureFlow | Analisis estatico de SQL Injection",
        "=" * 68,
        f"Objetivo    : {result.root}",
        f"Frontend    : {result.frontend}",
        f"Perfil      : {result.profile}",
        "",
        "RESUMEN",
        f"  Archivos analizados : {result.files_analyzed}/{result.files_total}",
        f"  Funciones analizadas: {result.functions_analyzed}",
        f"  Archivos con errores: {result.files_with_errors}",
        f"  Archivos parciales  : {result.files_partial}",
    ]
    if result.nodes_total:
        covered = result.nodes_supported + result.nodes_approximated
        lines.extend(
            [
                f"  Cobertura del AST   : {result.coverage_ratio:.1%} "
                f"({covered}/{result.nodes_total} nodos)",
                f"  Nodos aproximados   : {result.nodes_approximated}",
                f"  Nodos ignorados     : {result.nodes_ignored}",
            ]
        )
    else:
        lines.append("  Cobertura del AST   : no disponible para este frontend")
    lines.extend(
        [
            f"  Ocurrencias internas sin enlace: {result.unresolved_calls}",
            f"  Usos de APIs externas conserv. : {result.conservative_calls}",
        ]
    )
    lines.append("")

    if result.findings:
        count = len(result.findings)
        if count == 1:
            lines.append("RESULTADO: SE DETECTO 1 VULNERABILIDAD")
        else:
            lines.append(f"RESULTADO: SE DETECTARON {count} VULNERABILIDADES")
        for index, finding in enumerate(result.findings, start=1):
            sources = ", ".join(finding.sources) or "fuente desconocida"
            lines.extend(
                [
                    "",
                    f"[{index}] {finding.severity} | {finding.rule_id}",
                    f"    Ubicacion : {finding.file}:{finding.line} "
                    f"({finding.function}())",
                    f"    Flujo     : {sources} -> {finding.tainted_arg} "
                    f"-> {finding.sink}",
                    f"    Detalle   : {finding.message}",
                ]
            )
    else:
        lines.extend(
            [
                "RESULTADO: NO SE DETECTARON VULNERABILIDADES",
                "  No se encontro un flujo de entrada Flask no confiable hacia SQL.",
            ]
        )

    needs_review = (
        result.files_with_errors
        or result.files_partial
        or result.nodes_ignored
        or result.unresolved_calls
    )
    lines.extend(["", "INTERPRETACION"])
    if needs_review:
        reasons: list[str] = []
        if result.files_with_errors:
            reasons.append(f"{result.files_with_errors} archivos con error")
        if result.files_partial or result.nodes_ignored:
            reasons.append(
                f"{result.nodes_ignored} nodos ignorados en "
                f"{result.files_partial} archivos parciales"
            )
        if result.unresolved_calls:
            reasons.append(
                f"{result.unresolved_calls} ocurrencias internas sin enlace"
            )
        lines.append(f"  Revision recomendada: {'; '.join(reasons)}.")
        unresolved = sorted(
            {
                call
                for file_report in result.files
                for call in file_report.unresolved_calls
            }
        )
        if unresolved:
            lines.append(f"  Llamadas internas pendientes: {', '.join(unresolved)}")
    else:
        lines.append(
            "  No hubo errores, nodos ignorados ni llamadas internas sin enlace."
        )
    if result.conservative_calls:
        lines.append(
            "  Las APIs externas se trataron con propagacion conservadora de taint; "
            "no son errores de enlace."
        )
    return "\n".join(lines)


def _sarif(result: ScanResult) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureFlow",
                        "informationUri": "https://github.com/JLtz00/secureFlow",
                        "rules": [
                            {
                                "id": "PY.FLASK.SQLI",
                                "name": "Flask SQL injection",
                                "shortDescription": {
                                    "text": "Tainted Flask request data reaches a raw SQL execution sink."
                                },
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "results": [_sarif_result(finding) for finding in result.findings],
                "invocations": [
                    {
                        "executionSuccessful": result.files_with_errors == 0,
                        "properties": {
                            "profile": result.profile,
                            "frontend": result.frontend,
                            "filesTotal": result.files_total,
                            "filesAnalyzed": result.files_analyzed,
                            "filesWithErrors": result.files_with_errors,
                            "filesPartial": result.files_partial,
                            "functionsAnalyzed": result.functions_analyzed,
                            "nodesSupported": result.nodes_supported,
                            "nodesApproximated": result.nodes_approximated,
                            "nodesIgnored": result.nodes_ignored,
                            "coverageRatio": result.coverage_ratio,
                            "unresolvedCalls": result.unresolved_calls,
                            "conservativeCalls": result.conservative_calls,
                        },
                    }
                ],
            }
        ],
    }


def _sarif_result(finding: ScanFinding) -> dict:
    return {
        "ruleId": finding.rule_id,
        "level": "error",
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {"startLine": finding.line},
                },
                "logicalLocations": [{"name": finding.function, "kind": "function"}],
            }
        ],
        "properties": {
            "sink": finding.sink,
            "taintedArg": finding.tainted_arg,
            "sources": finding.sources,
        },
    }


def run_scan(args: argparse.Namespace) -> int:
    if not args.path.exists():
        print(f"secureflow: la ruta no existe: {args.path}", file=sys.stderr)
        return 2
    if args.path.is_file() and args.path.suffix != ".py":
        print(
            f"secureflow: el archivo debe tener extension .py: {args.path}",
            file=sys.stderr,
        )
        return 2

    profile = get_profile(args.profile)
    if args.models:
        profile = load_profile(args.models, base=profile)
    exclude_dirs = set(ProjectScanner.DEFAULT_EXCLUDE_DIRS) | set(args.exclude)
    scanner = ProjectScanner(
        args.path,
        frontend=args.frontend,
        profile=profile,
        exclude_dirs=exclude_dirs,
    )
    result = scanner.scan()
    if not result.files_total:
        print(
            f"secureflow: no se encontraron archivos Python en: {args.path}",
            file=sys.stderr,
        )
        return 2

    if args.format == "text":
        text = _text_report(result)
    else:
        payload = _sarif(result) if args.format == "sarif" else result.to_dict()
        text = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"Reporte guardado en: {args.output}")
    else:
        print(text)
    return 1 if result.findings and args.fail_on_findings else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secureflow", description="SecureFlow Flask SAST")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", description="Scan a Flask project for SQL injection")
    scan.add_argument("path", type=Path)
    scan.add_argument("--profile", default="flask", choices=["flask"])
    scan.add_argument("--frontend", default="python-ast", choices=["python-ast", "custom"])
    scan.add_argument(
        "--models",
        type=Path,
        help="TOML file extending sources, sinks, sanitizers, and database models",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="DIR",
        help="Directory name to exclude; may be repeated",
    )
    scan.add_argument(
        "--format",
        default="text",
        choices=["text", "json", "sarif"],
        help="Output format (default: text)",
    )
    scan.add_argument("-o", "--output", type=Path)
    scan.add_argument("--fail-on-findings", action="store_true")
    scan.set_defaults(func=run_scan)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        raise SystemExit(2)
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
