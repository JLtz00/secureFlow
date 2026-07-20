"""Command-line scanner for SecureFlow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from analyzer.project_scanner import ProjectScanner, ScanFinding, ScanResult


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
                            "filesTotal": result.files_total,
                            "filesAnalyzed": result.files_analyzed,
                            "filesWithErrors": result.files_with_errors,
                            "functionsAnalyzed": result.functions_analyzed,
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
    scanner = ProjectScanner(args.path)
    result = scanner.scan()
    payload = _sarif(result) if args.format == "sarif" else result.to_dict()
    text = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(text)
    else:
        print(text)
    return 1 if result.findings and args.fail_on_findings else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secureflow", description="SecureFlow Flask SAST")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", description="Scan a Flask project for SQL injection")
    scan.add_argument("path", type=Path)
    scan.add_argument("--profile", default="flask", choices=["flask"])
    scan.add_argument("--format", default="json", choices=["json", "sarif"])
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

