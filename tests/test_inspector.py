"""Tests for end-to-end archive inspection."""

from __future__ import annotations

import zipfile

from conftest import build_fat, build_ipa, build_macho, build_profile, default_info
from ipalab.inspector import ERROR, WARNING, find_ipa_files, inspect_ipa


def _codes(report):
    return {issue.code for issue in report.issues}


def test_valid_archive_has_no_error_findings(valid_ipa):
    report = inspect_ipa(valid_ipa)

    assert report.bundle_id == "com.example.demo"
    assert report.display_name == "Demo App"
    assert report.version == "1.4.2"
    assert report.build == "77"
    assert report.minimum_os == "15.0"
    assert report.sdk == "iphoneos17.4"
    assert report.platform == "iphoneos"
    assert report.executable == "Demo"
    assert report.architectures == ("arm64",)
    assert report.code_signed and report.pie
    assert report.encrypted is False
    assert report.device_families == (1, 2)
    assert report.has_provisioning_profile
    assert report.has_code_resources
    assert not [i for i in report.issues if i.severity == ERROR]


def test_entitlements_are_extracted(valid_ipa):
    report = inspect_ipa(valid_ipa)

    assert report.entitlements["application-identifier"] == "ABCDE12345.com.example.demo"
    assert report.entitlements["get-task-allow"] is False


def test_label_is_human_readable(valid_ipa):
    assert inspect_ipa(valid_ipa).label == "Demo App (com.example.demo) 1.4.2 77"


def test_unsigned_binary_is_an_error(unsigned_ipa):
    report = inspect_ipa(unsigned_ipa)

    assert "unsigned-binary" in _codes(report)
    assert "pie-missing" in _codes(report)
    assert report.worst_severity == ERROR


def test_universal_binary_is_detected(tmp_path):
    blob = build_fat([build_macho(), build_macho(cpu_type=0x01000007)])
    path = build_ipa(tmp_path / "fat.ipa", macho=blob)
    report = inspect_ipa(path)

    assert report.universal
    assert report.architectures == ("arm64", "x86_64")
    assert "no-arm64" not in _codes(report)


def test_missing_arm64_is_flagged(tmp_path):
    path = build_ipa(tmp_path / "x86.ipa", macho=build_macho(cpu_type=0x01000007))
    assert "no-arm64" in _codes(inspect_ipa(path))


def test_encrypted_binary_is_reported(tmp_path):
    path = build_ipa(tmp_path / "enc.ipa", macho=build_macho(encrypted=True))
    report = inspect_ipa(path)

    assert report.encrypted
    assert "fairplay-encrypted" in _codes(report)


def test_missing_provisioning_profile(tmp_path):
    path = build_ipa(tmp_path / "noprov.ipa", include_profile=False)
    assert "no-provisioning-profile" in _codes(inspect_ipa(path))


def test_unreadable_profile_is_a_warning(tmp_path):
    path = build_ipa(
        tmp_path / "badprov.ipa",
        profile=b"bplist00" + b"\xff" * 64,
    )
    assert "unreadable-profile" in _codes(inspect_ipa(path))


def test_profile_without_entitlements(tmp_path):
    path = build_ipa(
        tmp_path / "noent.ipa",
        profile=build_profile(entitlements={}),
    )
    report = inspect_ipa(path)

    assert report.entitlements == {}
    assert "no-entitlements" in _codes(report)


def test_missing_bundle_id_is_an_error(tmp_path):
    info = default_info()
    del info["CFBundleIdentifier"]
    path = build_ipa(tmp_path / "nobid.ipa", info=info)

    assert "missing-bundle-id" in _codes(inspect_ipa(path))


def test_missing_minimum_os_is_a_warning(tmp_path):
    info = default_info()
    del info["MinimumOSVersion"]
    path = build_ipa(tmp_path / "nomin.ipa", info=info)

    assert "missing-minimum-os" in _codes(inspect_ipa(path))


def test_missing_executable_is_an_error(tmp_path):
    raw = tmp_path / "noexe.ipa"
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr(
            "Payload/Demo.app/Info.plist",
            __import__("plistlib").dumps(default_info()),
        )

    report = inspect_ipa(str(raw))
    assert "missing-executable" in _codes(report)
    assert report.worst_severity == ERROR


def test_no_app_bundle(tmp_path):
    raw = tmp_path / "empty.ipa"
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("readme.txt", "nothing here")

    assert "no-app-bundle" in _codes(inspect_ipa(str(raw)))


def test_not_an_archive(not_an_ipa):
    report = inspect_ipa(not_an_ipa)
    assert "not-an-archive" in _codes(report)
    assert report.worst_severity == ERROR


def test_multiple_bundles_picks_first(tmp_path):
    raw = tmp_path / "two.ipa"
    with zipfile.ZipFile(raw, "w") as archive:
        for name in ("Alpha.app", "Beta.app"):
            archive.writestr(f"Payload/{name}/Info.plist", __import__("plistlib").dumps(default_info()))
            archive.writestr(f"Payload/{name}/Demo", build_macho())

    report = inspect_ipa(str(raw))
    assert "multiple-bundles" in _codes(report)
    assert report.executable == "Demo"


def test_report_serialises_to_plain_types(valid_ipa):
    import json

    payload = inspect_ipa(valid_ipa).as_dict()
    assert json.loads(json.dumps(payload))["bundle_id"] == "com.example.demo"


def test_find_ipa_files_walks_recursively(tmp_path):
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    build_ipa(nested / "one.ipa")
    build_ipa(tmp_path / "two.ipa")
    (tmp_path / "not_an_ipa.txt").write_text("ignore me")

    found = find_ipa_files(str(tmp_path))
    assert len(found) == 2
    assert all(path.endswith(".ipa") for path in found)
    assert found == sorted(found)


def test_find_ipa_files_accepts_a_single_path(valid_ipa):
    assert find_ipa_files(valid_ipa) == [valid_ipa]


def test_warning_is_reported_as_warning(tmp_path):
    info = default_info()
    del info["MinimumOSVersion"]
    path = build_ipa(tmp_path / "warn.ipa", info=info)
    report = inspect_ipa(path)

    assert report.worst_severity == WARNING
    assert all(i.severity != ERROR for i in report.issues)
