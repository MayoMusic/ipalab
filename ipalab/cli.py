"""Command line entry point for IPA Lab."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, Sequence

from . import __version__
from .inspector import ERROR, Report, find_ipa_files, inspect_ipa

_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_RESET = "\033[0m"

_COLOURS = {ERROR: _RED, "warning": _YELLOW, "info": _CYAN}

_LABEL_WIDTH = 18


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipalab",
        description="Read-only inspector for iOS .ipa archives.",
    )
    parser.add_argument("--version", action="version", version=f"ipalab {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--no-colour",
        action="store_true",
        help="disable ANSI colour in output",
    )

    inspect = subparsers.add_parser(
        "inspect", parents=[common], help="inspect one or more .ipa files"
    )
    inspect.add_argument("paths", nargs="+", help="paths to .ipa files")
    inspect.add_argument("--json", action="store_true", help="emit JSON instead of text")
    inspect.set_defaults(handler=_cmd_inspect)

    scan = subparsers.add_parser(
        "scan", parents=[common], help="recursively inspect every .ipa beneath a directory"
    )
    scan.add_argument("root", help="directory to search")
    scan.add_argument("--json", action="store_true", help="emit JSON instead of text")
    scan.add_argument(
        "--quiet",
        action="store_true",
        help="only report archives with error or warning findings",
    )
    scan.set_defaults(handler=_cmd_scan)

    return parser


def _cmd_inspect(args: argparse.Namespace) -> int:
    reports = [inspect_ipa(path) for path in args.paths]
    _emit(reports, as_json=args.json, colour=not args.no_colour)
    return _exit_code(reports)


def _cmd_scan(args: argparse.Namespace) -> int:
    paths = find_ipa_files(args.root)
    if not paths:
        print(f"No .ipa files found under {args.root}", file=sys.stderr)
        return 0

    reports = [inspect_ipa(path) for path in paths]
    if args.quiet:
        reports = [
            report
            for report in reports
            if report.worst_severity in (ERROR, "warning")
        ]
    _emit(reports, as_json=args.json, colour=not args.no_colour)
    return _exit_code(reports)


def _exit_code(reports: List[Report]) -> int:
    """Exit non-zero if any archive reported an error-severity finding."""
    return 1 if any(report.worst_severity == ERROR for report in reports) else 0


def _emit(reports: List[Report], as_json: bool, colour: bool) -> None:
    if as_json:
        print(json.dumps([report.as_dict() for report in reports], indent=2))
        return
    for report in reports:
        _print_report(report, colour)


def _print_report(report: Report, colour: bool) -> None:
    heading = report.label
    if colour:
        heading = f"{_BOLD}{heading}{_RESET}"
    print(heading)

    rows = [
        ("archive", report.path),
        ("minimum OS", report.minimum_os),
        ("sdk", report.sdk),
        ("architectures", ", ".join(report.architectures) or "unknown"),
        ("container", "universal (fat)" if report.universal else "single slice"),
        ("code signed", _yes_no(report.code_signed)),
        ("PIE / ASLR", _yes_no(report.pie)),
        ("fairplay", _yes_no(report.encrypted)),
        (
            "provisioning",
            "embedded" if report.has_provisioning_profile else "none",
        ),
        ("code resources", _yes_no(report.has_code_resources)),
    ]
    if report.device_families:
        rows.append(("device families", ", ".join(map(str, report.device_families))))
    if report.linked_libraries:
        rows.append(("linked dylibs", str(len(report.linked_libraries))))
    if report.certificate_subjects:
        rows.append(("certificates", ", ".join(report.certificate_subjects[:3])))
    if report.entitlements:
        rows.append(("entitlements", ", ".join(sorted(report.entitlements))))

    for label, value in rows:
        if value is None:
            continue
        print(f"  {_dim(label.ljust(_LABEL_WIDTH), colour)}{value}")

    if report.issues:
        print("  findings:")
        for issue in report.issues:
            print(f"    {_severity(issue.severity, colour)} {issue.message}")
    print()


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _severity(severity: str, colour: bool) -> str:
    label = f"[{severity}]"
    if not colour:
        return label
    return f"{_COLOURS.get(severity, '')}{label}{_RESET}"


def _dim(text: str, colour: bool) -> str:
    return f"{_DIM}{text}{_RESET}" if colour else text


if __name__ == "__main__":
    raise SystemExit(main())
