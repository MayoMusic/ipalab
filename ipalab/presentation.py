"""Formatting helpers that turn a :class:`~ipalab.inspector.Report` into rows.

Kept separate from the GUI so that presentation logic can be tested headlessly.
Everything here is pure: same report in, same rows out.
"""

from __future__ import annotations

import json
import os
from typing import Any, List, Tuple

from .inspector import Report

Row = Tuple[str, str]

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}

_DEVICE_FAMILIES = {1: "iPhone", 2: "iPad"}

_UNSET = "—"

_MAX_INLINE = 6


def format_value(value: Any) -> str:
    """Render a decoded property list value as a single display string."""
    if value is None:
        return _UNSET
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, str):
        return value if value.strip() else _UNSET
    if isinstance(value, (list, tuple)):
        if not value:
            return _UNSET
        return ", ".join(format_value(item) for item in value)
    if isinstance(value, dict):
        if not value:
            return _UNSET
        return json.dumps(value, sort_keys=True, separators=(", ", ": "))
    return str(value)


def human_size(num_bytes: float) -> str:
    """Format a byte count with a binary unit suffix."""
    if num_bytes < 1024:
        return f"{int(num_bytes)} B"
    value = float(num_bytes)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024.0
        if value < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}"
    return f"{value:.1f} TB"


def archive_size(report: Report) -> str:
    try:
        return human_size(os.path.getsize(report.path))
    except OSError:
        return _UNSET


def summary_line(report: Report) -> str:
    """A one-line identity string: name, bundle id and version."""
    parts = []
    name = report.display_name or report.bundle_name
    if name:
        parts.append(name)
    if report.bundle_id:
        parts.append(report.bundle_id)

    version = report.version or "?"
    if report.build:
        version = f"{version} ({report.build})"
    parts.append(version)
    return "   ".join(parts)


def metadata_rows(report: Report) -> List[Row]:
    families = ", ".join(_DEVICE_FAMILIES.get(f, str(f)) for f in report.device_families)
    return [
        ("Bundle identifier", format_value(report.bundle_id)),
        ("Display name", format_value(report.display_name)),
        ("Name", format_value(report.bundle_name)),
        ("Version", format_value(report.version)),
        ("Build", format_value(report.build)),
        ("Minimum iOS", format_value(report.minimum_os)),
        ("SDK", format_value(report.sdk)),
        ("Platform", format_value(report.platform)),
        ("Executable", format_value(report.executable)),
        ("Device families", format_value(families)),
        ("Archive size", archive_size(report)),
    ]


def binary_rows(report: Report) -> List[Row]:
    libraries = list(report.linked_libraries)
    if libraries:
        shown = libraries[:_MAX_INLINE]
        more = len(libraries) - len(shown)
        linked = f"{len(libraries)}   " + ", ".join(shown)
        if more > 0:
            linked += f"   (+{more} more)"
    else:
        linked = _UNSET

    return [
        ("Architectures", format_value(list(report.architectures))),
        ("Container", "universal (fat)" if report.universal else "single slice"),
        ("Code signed", format_value(report.code_signed)),
        ("PIE / ASLR", format_value(report.pie)),
        ("FairPlay encrypted", format_value(report.encrypted)),
        ("Linked dylibs", linked),
        ("Provisioning profile", "embedded" if report.has_provisioning_profile else "none"),
        ("Code resources", format_value(report.has_code_resources)),
        ("Certificates", format_value(list(report.certificate_subjects))),
    ]


def entitlement_rows(report: Report) -> List[Row]:
    return [(key, format_value(value)) for key, value in sorted(report.entitlements.items())]


def ordered_findings(report: Report) -> List[Tuple[str, str, str]]:
    """Findings as ``(severity, code, message)`` tuples, worst first."""
    ordered = sorted(
        report.issues, key=lambda issue: _SEVERITY_ORDER.get(issue.severity, 9)
    )
    return [(issue.severity, issue.code, issue.message) for issue in ordered]


def counts_by_severity(report: Report) -> dict:
    counts = {"error": 0, "warning": 0, "info": 0}
    for issue in report.issues:
        if issue.severity in counts:
            counts[issue.severity] += 1
    return counts
