# IPA Lab

A read-only inspector for iOS `.ipa` archives. It reports what an archive
contains and what is wrong with it — bundle metadata, provisioning-profile
entitlements, Mach-O architecture and signing posture — with severity-ranked
findings and a non-zero exit code when something is actually broken.

```
pip install ipalab
```

## Scope, and what this is not

IPA Lab **only ever reads**. There is no code anywhere in this package that
writes, patches, injects into, strips, re-signs, or re-packages an archive. It
is a diagnostics tool, nothing more.

It is also not a sideloader. It does not talk to devices, install anything, or
install itself as a background service. If you need to get an app onto a
device you own, use the first-party toolchain — Xcode, `xcrun devicectl`, or
[`pymobiledevice3`](https://github.com/doronz88/pymobiledevice3) — and use
IPA Lab to answer "why won't this build run?".

## Install

```bash
pip install ipalab                 # core
pip install "ipalab[certs]"        # + certificate subject extraction
```

Python 3.9+. No required dependencies; the standard library covers everything
except optional certificate reporting.

### Windows executable

A standalone `ipalab.exe` is attached to every CI run — no Python installation
needed. Download it from the **Actions** tab on any successful run
(`Windows executable` job, artifact `ipalab-windows-x64`), or build it
yourself:

```powershell
pip install -e ".[dev]" pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --console --name ipalab `
    --paths . --distpath dist --workpath build scripts\ipalab_entry.py
.\dist\ipalab.exe scan .\samples
```

## Usage

Inspect one or more archives:

```bash
ipalab inspect MyApp.ipa
ipalab inspect *.ipa --json
```

Recursively audit a directory, showing only archives that have findings:

```bash
ipalab scan ~/Downloads --quiet
```

Exit codes are script-friendly: `0` when nothing worse than a warning was
found, `1` when any archive produced an error-severity finding.

### Example

```
$ ipalab inspect MyApp.ipa
Reader (com.example.reader) 2.1.0 (412)
  archive: /home/me/MyApp.ipa
  minimum OS: 15.0
  sdk: iphoneos17.4
  architectures: arm64
  container: single slice
  code signed: yes
  PIE / ASLR: yes
  fairplay: no
  provisioning: embedded
  code resources: yes
  device families: 1, 2
  linked dylibs: 14
  entitlements: application-identifier, get-task-allow, keychain-access-groups
  findings:
    [warning] MinimumOSVersion is absent; the bundle may install on unsupported system versions.
```

## What it inspects

| Area | Detail |
| --- | --- |
| Bundle | `CFBundleIdentifier`, display name, version/build, `MinimumOSVersion`, SDK, device families |
| Entitlements | The property list is lifted out of the DER `PKCS#7` wrapper in `embedded.mobileprovision` |
| Certificates | Common names, when the `certs` extra is installed |
| Mach-O | Universal container detection, per-slice architecture (including `arm64e` vs `arm64v8`), file type |
| Signing | `LC_CODE_SIGNATURE` presence, `MH_PIE`, linked dylibs, `_CodeSignature/CodeResources` |
| Encryption | `LC_ENCRYPTION_INFO(_64)` cryptid — flags FairPlay-protected builds |

### Finding codes

`error`

- `not-an-archive` — the file is not a valid ZIP
- `no-app-bundle` — no `Payload/*.app` directory
- `missing-info-plist` — `Info.plist` absent or undecodable
- `missing-bundle-id` — no `CFBundleIdentifier`
- `missing-executable` — declared executable not in the bundle
- `unreadable-executable` — not parseable as Mach-O
- `unsigned-binary` — no `LC_CODE_SIGNATURE`

`warning`

- `multiple-bundles` — more than one `.app` present
- `missing-minimum-os` — no `MinimumOSVersion`
- `pie-missing` — no `MH_PIE`, so ASLR will not apply
- `no-arm64` — will not run on modern iOS hardware
- `unreadable-profile` / `no-entitlements` — provisioning profile problems

`info`

- `fairplay-encrypted` — App Store release channel only
- `no-provisioning-profile` — probably built through Xcode

## Library use

```python
from ipalab.inspector import inspect_ipa

report = inspect_ipa("MyApp.ipa")
print(report.bundle_id, report.architectures)
print(report.worst_severity)
for issue in report.issues:
    print(issue.severity, issue.code, issue.message)
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Tests generate every fixture in memory — including the Mach-O images and the
CMS-wrapped provisioning profiles — so the suite carries no binary blobs.

CI runs the lint and test matrix across Linux, macOS and Windows on Python
3.9–3.13, builds an sdist and wheel, and smoke-tests the installed
distribution. Pushing a `v*` tag publishes to PyPI via trusted publishing.

## Licence

MIT. See [LICENSE](LICENSE).