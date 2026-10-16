"""Read-only analysis of an ``.ipa`` archive.

Walks the archive, locates the application bundle under ``Payload/`` and
assembles a :class:`Report` describing its metadata, signing posture and any
problems worth flagging.  Nothing in this module mutates the archive.
"""

from __future__ import annotations

import os
import plistlib
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import macho
from . import plist as plist_util

ERROR = "error"
WARNING = "warning"
INFO = "info"

_SEVERITY_ORDER = {ERROR: 0, WARNING: 1, INFO: 2}


@dataclass(frozen=True)
class Issue:
    """A single finding, ranked by ``severity``."""

    severity: str
    code: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {"severity": self.severity, "code": self.code, "message": self.message}


@dataclass
class Report:
    """Everything ``ipalab`` learned about one archive."""

    path: str
    bundle_id: Optional[str] = None
    bundle_name: Optional[str] = None
    display_name: Optional[str] = None
    version: Optional[str] = None
    build: Optional[str] = None
    minimum_os: Optional[str] = None
    sdk: Optional[str] = None
    platform: Optional[str] = None
    executable: Optional[str] = None
    architectures: Tuple[str, ...] = ()
    universal: bool = False
    code_signed: bool = False
    pie: bool = False
    encrypted: bool = False
    has_provisioning_profile: bool = False
    has_code_resources: bool = False
    entitlements: Dict[str, Any] = field(default_factory=dict)
    certificate_subjects: Tuple[str, ...] = ()
    linked_libraries: Tuple[str, ...] = ()
    device_families: Tuple[int, ...] = ()
    issues: List[Issue] = field(default_factory=list)

    @property
    def label(self) -> str:
        name = self.display_name or self.bundle_name or "unknown"
        parts = [self.version or "?"]
        if self.build:
            parts.append(self.build)
        return f"{name} ({self.bundle_id or 'no bundle id'}) {' '.join(parts)}"

    @property
    def worst_severity(self) -> Optional[str]:
        if not self.issues:
            return None
        return min(self.issues, key=lambda i: _SEVERITY_ORDER.get(i.severity, 9)).severity

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "label": self.label,
            "bundle_id": self.bundle_id,
            "name": self.bundle_name,
            "display_name": self.display_name,
            "version": self.version,
            "build": self.build,
            "minimum_os": self.minimum_os,
            "sdk": self.sdk,
            "platform": self.platform,
            "executable": self.executable,
            "architectures": list(self.architectures),
            "universal": self.universal,
            "code_signed": self.code_signed,
            "pie": self.pie,
            "encrypted": self.encrypted,
            "has_provisioning_profile": self.has_provisioning_profile,
            "has_code_resources": self.has_code_resources,
            "entitlements": self.entitlements,
            "certificate_subjects": list(self.certificate_subjects),
            "linked_libraries": list(self.linked_libraries),
            "device_families": list(self.device_families),
            "issues": [issue.as_dict() for issue in self.issues],
        }


def inspect_ipa(path: str) -> Report:
    """Analyse the archive at ``path`` and return a populated report."""
    report = Report(path=os.fspath(path))
    try:
        with zipfile.ZipFile(path) as archive:
            _inspect_archive(archive, report)
    except zipfile.BadZipFile as exc:
        report.issues.append(
            Issue(ERROR, "not-an-archive", f"Not a valid ZIP archive ({exc}).")
        )
    except OSError as exc:
        report.issues.append(Issue(ERROR, "unreadable", f"Could not read file: {exc}"))
    return report


def find_ipa_files(root: str) -> List[str]:
    """Return every ``.ipa`` file at or beneath ``root``, sorted."""
    if os.path.isfile(root):
        return [root]
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in filenames:
            if filename.lower().endswith(".ipa"):
                found.append(os.path.join(dirpath, filename))
    return sorted(found)


def _inspect_archive(archive: zipfile.ZipFile, report: Report) -> None:
    names = set(archive.namelist())

    bundles = sorted(
        {
            parts[1]
            for name in names
            for parts in [name.split("/")]
            if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app")
        }
    )
    if not bundles:
        report.issues.append(
            Issue(ERROR, "no-app-bundle", "No *.app bundle was found under Payload/.")
        )
        return
    if len(bundles) > 1:
        report.issues.append(
            Issue(
                WARNING,
                "multiple-bundles",
                f"Archive contains {len(bundles)} app bundles; "
                f"reporting '{bundles[0]}'.",
            )
        )

    bundle = bundles[0]
    prefix = f"Payload/{bundle}"

    info = _read_plist_member(archive, f"{prefix}/Info.plist")
    if info is None:
        report.issues.append(
            Issue(ERROR, "missing-info-plist", f"{prefix}/Info.plist could not be read.")
        )
        return

    _fill_metadata(report, info)
    _inspect_executable(archive, report, prefix, bundle, info)
    _inspect_signing(archive, report, prefix, names)


def _read_plist_member(archive: zipfile.ZipFile, name: str) -> Optional[dict]:
    try:
        payload = archive.read(name)
    except KeyError:
        return None
    try:
        value = plistlib.loads(payload)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _fill_metadata(report: Report, info: dict) -> None:
    report.bundle_id = _as_str(info.get("CFBundleIdentifier"))
    report.bundle_name = _as_str(info.get("CFBundleName"))
    report.display_name = _as_str(info.get("CFBundleDisplayName"))
    report.version = _as_str(info.get("CFBundleShortVersionString"))
    report.build = _as_str(info.get("CFBundleVersion"))
    report.minimum_os = _as_str(info.get("MinimumOSVersion"))
    report.sdk = _as_str(info.get("DTSDKName"))
    report.platform = _as_str(info.get("DTPlatformName"))

    families = info.get("UIDeviceFamily")
    if isinstance(families, (list, tuple)):
        report.device_families = tuple(f for f in families if isinstance(f, int))

    if not report.bundle_id:
        report.issues.append(
            Issue(ERROR, "missing-bundle-id", "CFBundleIdentifier is absent.")
        )
    if not report.minimum_os:
        report.issues.append(
            Issue(
                WARNING,
                "missing-minimum-os",
                "MinimumOSVersion is absent; the bundle may install on "
                "unsupported system versions.",
            )
        )


def _inspect_executable(
    archive: zipfile.ZipFile, report: Report, prefix: str, bundle: str, info: dict
) -> None:
    declared = _as_str(info.get("CFBundleExecutable"))
    executable = declared or bundle[: -len(".app")]
    report.executable = executable

    member = f"{prefix}/{executable}"
    try:
        blob = archive.read(member)
    except KeyError:
        report.issues.append(
            Issue(
                ERROR,
                "missing-executable",
                f"Declared executable '{executable}' is not present in the bundle.",
            )
        )
        return

    try:
        binary = macho.parse(blob)
    except macho.MachOError as exc:
        report.issues.append(
            Issue(ERROR, "unreadable-executable", f"Could not parse '{member}': {exc}")
        )
        return

    report.architectures = binary.architectures
    report.universal = binary.is_fat
    report.code_signed = binary.code_signed
    report.pie = binary.pie
    report.encrypted = binary.encrypted

    libraries = []
    for mach_slice in binary.slices:
        libraries.extend(mach_slice.linked_libraries)
    report.linked_libraries = tuple(dict.fromkeys(libraries))

    if not binary.code_signed:
        report.issues.append(
            Issue(
                ERROR,
                "unsigned-binary",
                "The executable carries no LC_CODE_SIGNATURE load command.",
            )
        )
    if not binary.pie:
        report.issues.append(
            Issue(
                WARNING,
                "pie-missing",
                "The executable does not set MH_PIE; ASLR will not apply.",
            )
        )
    if binary.encrypted:
        report.issues.append(
            Issue(
                INFO,
                "fairplay-encrypted",
                "The executable is FairPlay encrypted and only runs on the "
                "App Store release channel.",
            )
        )
    if "arm64" not in binary.architectures:
        report.issues.append(
            Issue(
                WARNING,
                "no-arm64",
                "No arm64 slice was found; this will not run on modern "
                "iOS devices.",
            )
        )


def _inspect_signing(
    archive: zipfile.ZipFile, report: Report, prefix: str, names: set
) -> None:
    report.has_code_resources = f"{prefix}/_CodeSignature/CodeResources" in names

    member = f"{prefix}/embedded.mobileprovision"
    if member not in names:
        report.issues.append(
            Issue(
                INFO,
                "no-provisioning-profile",
                "No embedded.mobileprovision; the bundle was most likely signed "
                "through the Xcode build system.",
            )
        )
        return

    report.has_provisioning_profile = True
    blob = archive.read(member)
    report.certificate_subjects = tuple(_certificate_subjects(blob))

    profile = plist_util.extract_plist(blob)
    if not isinstance(profile, dict):
        report.issues.append(
            Issue(
                WARNING,
                "unreadable-profile",
                "The provisioning profile is present but its property list "
                "could not be extracted.",
            )
        )
        return

    entitlements = profile.get("Entitlements")
    report.entitlements = _jsonable(entitlements) if isinstance(entitlements, dict) else {}

    if not report.entitlements:
        report.issues.append(
            Issue(
                WARNING,
                "no-entitlements",
                "The provisioning profile declares no Entitlements dictionary.",
            )
        )


def _certificate_subjects(der: bytes) -> List[str]:
    """Return common names from a PKCS#7 blob, if ``cryptography`` is present."""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        from cryptography.x509.oid import NameOID
    except Exception:
        return []
    try:
        certificates = pkcs7.load_der_pkcs7_certificates(der)
    except Exception:
        return []
    subjects = []
    for certificate in certificates:
        attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attributes:
            subjects.append(attributes[0].value)
    return subjects


def _as_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _jsonable(value: Any) -> Any:
    """Coerce a decoded property list into something ``json`` can serialise."""
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
