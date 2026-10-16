"""Tests for the command line surface."""

from __future__ import annotations

import json

from conftest import build_ipa, build_macho, default_info
from ipalab.cli import main


def test_inspect_prints_a_report(valid_ipa, capsys):
    assert main(["inspect", valid_ipa, "--no-colour"]) == 0

    out = capsys.readouterr().out
    assert "Demo App" in out
    assert "com.example.demo" in out
    assert "arm64" in out


def test_inspect_json_output(valid_ipa, capsys):
    assert main(["inspect", valid_ipa, "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["bundle_id"] == "com.example.demo"
    assert payload[0]["architectures"] == ["arm64"]


def test_inspect_json_accepts_multiple_archives(tmp_path, capsys):
    first = build_ipa(tmp_path / "one.ipa")
    second = build_ipa(
        tmp_path / "two.ipa",
        info=default_info(CFBundleIdentifier="com.example.two"),
    )

    assert main(["inspect", first, second, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [entry["bundle_id"] for entry in payload] == [
        "com.example.demo",
        "com.example.two",
    ]


def test_error_findings_produce_exit_code_one(unsigned_ipa, capsys):
    assert main(["inspect", unsigned_ipa, "--no-colour"]) == 1
    assert "unsigned" in capsys.readouterr().out


def test_scan_directory(tmp_path, capsys):
    nested = tmp_path / "nested"
    nested.mkdir()
    build_ipa(nested / "demo.ipa")

    assert main(["scan", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1


def test_scan_reports_when_nothing_matches(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == 0
    assert "No .ipa files found" in capsys.readouterr().err


def test_scan_quiet_filters_clean_archives(tmp_path, capsys):
    build_ipa(tmp_path / "clean.ipa")
    build_ipa(tmp_path / "dirty.ipa", macho=build_macho(code_signed=False))

    # --quiet keeps only archives that have something to report.
    assert main(["scan", str(tmp_path), "--quiet", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    assert "dirty.ipa" in payload[0]["path"]


def test_module_entry_point_is_importable():
    import ipalab.__main__ as entry

    assert entry.main is not None
