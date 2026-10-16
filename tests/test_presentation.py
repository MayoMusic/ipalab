"""Tests for the presentation helpers.

These are pure functions, so they are tested without any GUI toolkit present.
"""

from __future__ import annotations

import pytest

from conftest import build_ipa, build_macho, default_info
from ipalab import presentation
from ipalab.inspector import inspect_ipa


def test_format_value_scalars():
    assert presentation.format_value(True) == "yes"
    assert presentation.format_value(False) == "no"
    assert presentation.format_value(None) == presentation._UNSET
    assert presentation.format_value("") == presentation._UNSET
    assert presentation.format_value("hi") == "hi"
    assert presentation.format_value(42) == "42"
    assert presentation.format_value(b"\x01\x02") == "0102"


def test_format_value_collections():
    assert presentation.format_value([]) == presentation._UNSET
    assert presentation.format_value(["a", "b"]) == "a, b"
    assert presentation.format_value({"k": True}) == '{"k": true}'


def test_human_size():
    assert presentation.human_size(512) == "512 B"
    assert presentation.human_size(2048) == "2.0 KB"
    assert presentation.human_size(9_500_000) == "9.1 MB"
    assert presentation.human_size(3 * 1024**3) == "3.0 GB"


def test_summary_line(valid_ipa):
    assert presentation.summary_line(inspect_ipa(valid_ipa)) == (
        "Demo App   com.example.demo   1.4.2 (77)"
    )


def test_metadata_rows_are_complete(valid_ipa):
    rows = dict(presentation.metadata_rows(inspect_ipa(valid_ipa)))

    assert rows["Bundle identifier"] == "com.example.demo"
    assert rows["Minimum iOS"] == "15.0"
    assert rows["Device families"] == "iPhone, iPad"
    assert rows["Archive size"].endswith(("B", "KB", "MB"))


def test_binary_rows(valid_ipa):
    rows = dict(presentation.binary_rows(inspect_ipa(valid_ipa)))

    assert rows["Architectures"] == "arm64"
    assert rows["Container"] == "single slice"
    assert rows["Code signed"] == "yes"
    assert rows["PIE / ASLR"] == "yes"
    assert rows["FairPlay encrypted"] == "no"
    assert rows["Provisioning profile"] == "embedded"
    assert rows["Linked dylibs"].startswith("1   /usr/lib/libSystem.B.dylib")


def test_linked_dylibs_are_capped_and_counted(tmp_path):
    names = [f"/usr/lib/lib{i}.dylib" for i in range(10)]
    path = build_ipa(tmp_path / "many.ipa", macho=build_macho(dylibs=names))
    value = dict(presentation.binary_rows(inspect_ipa(path)))["Linked dylibs"]

    assert value.startswith("10   ")
    assert "(+4 more)" in value


def test_entitlement_rows_are_sorted(valid_ipa):
    rows = presentation.entitlement_rows(inspect_ipa(valid_ipa))
    keys = [key for key, _ in rows]

    assert keys == sorted(keys)
    assert "application-identifier" in keys


def test_ordered_findings_puts_errors_first(unsigned_ipa):
    findings = presentation.ordered_findings(inspect_ipa(unsigned_ipa))
    severities = [severity for severity, _code, _message in findings]

    assert severities == sorted(severities, key=lambda s: {"error": 0, "warning": 1, "info": 2}[s])
    assert "unsigned-binary" in [code for _s, code, _m in findings]


def test_counts_by_severity(tmp_path):
    path = build_ipa(tmp_path / "mixed.ipa", macho=build_macho(encrypted=True, code_signed=False))
    counts = presentation.counts_by_severity(inspect_ipa(path))

    assert counts["error"] >= 1
    assert counts["info"] >= 1


def test_archive_size_missing_file(valid_ipa):
    report = inspect_ipa(valid_ipa)
    report.path = "does-not-exist.ipa"
    assert presentation.archive_size(report) == presentation._UNSET


def test_clean_archive_has_no_findings(valid_ipa):
    assert presentation.ordered_findings(inspect_ipa(valid_ipa)) == []


@pytest.mark.parametrize("missing", ["CFBundleIdentifier", "MinimumOSVersion"])
def test_missing_keys_render_as_unset(tmp_path, missing):
    info = default_info()
    del info[missing]
    path = build_ipa(tmp_path / f"{missing}.ipa", info=info)
    rows = dict(presentation.metadata_rows(inspect_ipa(path)))

    label = "Bundle identifier" if missing == "CFBundleIdentifier" else "Minimum iOS"
    assert rows[label] == presentation._UNSET
