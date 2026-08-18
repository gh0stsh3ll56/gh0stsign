# Gh0stSign

**Code-signing & binary-integrity validation for application-security pentesting**
Ghost Ops Security / Kill Chain Replay — v2.0.0 — **Authorized Use Only**

Gh0stSign walks an application install (or a single file) and validates the
code-signing and file-permission posture of every executable artifact it
finds: unsigned binaries, tampered signatures, weak crypto, untrusted chains,
and the writable-file/writable-directory weaknesses that turn "unsigned" into
"trivially replaceable." Every finding is mapped to CWE, MITRE ATT&CK,
OWASP Top 10, NIST 800-53, and CIS Controls v8, and lands in a tabbed CLI
summary plus a client-ready Markdown report.

Single file, Python 3.10+, **zero third-party dependencies** — no pywin32, no
Sysinternals, nothing to install on the target.

---

## Why this matters on an appsec engagement

Unsigned or user-writable program files defeat the platform's entire trust
stack: application allowlisting (WDAC/AppLocker publisher rules), EDR trust
decisions, update integrity, and incident-response triage all assume binaries
are signed and immutable to standard users. A single unsigned, Users-writable
service binary is a straight privilege-escalation and persistence path —
OWASP **A08:2021 Software and Data Integrity Failures** in its most concrete
form.

## Checks

| ID | Check | Base severity |
|---|---|---|
| GS-01 | Tampered signature (Authenticode hash mismatch) | CRITICAL |
| GS-02 | Unsigned kernel driver (`.sys` / native subsystem) | HIGH |
| GS-03 | Unsigned executable / library | HIGH |
| GS-04 | Untrusted or self-signed signing chain | HIGH |
| GS-05 | Binary writable by low-privileged users (Windows DACL) | HIGH |
| GS-06 | Install directory writable by low-privileged users (DLL-planting / search-order hijack surface) | HIGH |
| GS-07 | Expired or not-yet-valid signing certificate | MEDIUM |
| GS-08 | Weak signature digest (MD5 / SHA-1) | MEDIUM |
| GS-09 | Unsigned script (`.ps1` `.psm1` `.vbs` `.js` `.wsf` …) | MEDIUM |
| GS-10 | Signature missing timestamp countersignature | LOW |
| GS-11 | World/group-writable executable (POSIX) | HIGH / MEDIUM |

**Escalation rule:** an unsigned binary (GS-02/GS-03) that is *also* writable
by low-privileged users is raised to **CRITICAL** — that combination is a
direct code-planting path. Unsigned files get a SHA-256 hash recorded as
evidence.

Low-privileged identities checked on Windows: `Everyone`, `BUILTIN\Users`,
`Authenticated Users`, `INTERACTIVE`, `Domain Users`, `Guests` — any Allow ACE
granting write-class rights (Write/Modify/FullControl/CreateFiles/AppendData/
Delete/ChangePermissions/TakeOwnership) on a binary or its directory.

## Two scan modes

| | Windows (`windows-verify`) | Linux/other (`offline-pe-analysis`) |
|---|---|---|
| Engine | PowerShell `Get-AuthenticodeSignature` + `Get-Acl` (batched, no extra tools) | Built-in PE parser reading the Authenticode certificate table directly |
| Validates trust chain / revocation | ✅ | ❌ (presence ≠ validity) |
| Catalog signatures (most Microsoft OS files) | ✅ | ❌ — catalog-signed files show as `NotSigned(no cert table)` |
| Digest algorithm, signer CNs, timestamp presence | ✅ | ✅ (ASN.1 OID analysis of the PKCS#7 blob) |
| Permission review | DACL ACEs on files **and** their directories | POSIX world/group-writable bits |

Offline mode exists so you can assess Windows application dirs mounted or
copied onto the Kali box; the report states which mode produced each verdict
and carries the catalog-signing caveat automatically. **Re-run on Windows for
authoritative signature verdicts.**

## Usage

```
python3 gh0stsign.py <path> [options]

  path                 file or directory to assess (prompts if omitted)
  -r, --report PATH    Markdown report (default: gh0stsign_report.md)
  --json PATH          also write machine-readable findings JSON
  -v, --verbose        print each file's verdict while scanning
  --all-files          examine every file, not just executable/script extensions
  --no-acl             skip the Windows DACL review
  --max-files N        scan cap (default 20000)
  --top N              findings rows shown in the CLI table (default 25)
  --fail-on SEVERITY   exit 2 if any finding at/above this severity (CI gate)
```

### Examples

```bash
# full verification of an installed application (run on the Windows target)
python gh0stsign.py "C:\Program Files\TargetApp" -r targetapp.md --json targetapp.json

# offline assessment from Kali against a mounted/copied app directory
python3 gh0stsign.py "/mnt/target/Program Files/TargetApp"

# single binary
python3 gh0stsign.py ./service.exe

# CI / build-pipeline gate: fail the build if anything HIGH or worse
python3 gh0stsign.py dist/ --fail-on HIGH
```

Exit codes: `0` clean run, `1` bad path, `2` findings at/above `--fail-on`.

## Output

**CLI** — tabbed (aligned-column) tables: scan summary, findings grouped by
check and severity, top individual findings with evidence, and a publisher
inventory extracted from signer certificates.

**Markdown report** (`-r`) — engagement-ready:

- header block (tool/date/target/host/scan mode) and executive summary
- findings-by-severity table
- one section per check with a **control-mapping table**
  (CWE / MITRE ATT&CK / OWASP / NIST 800-53 / CIS v8), risk narrative,
  remediation guidance, and a per-file evidence table with severities
- signed-file inventory (status, signer, digest, timestamped, cert expiry)
- unsigned-file inventory with SHA-256 evidence hashes
- methodology & limitations (including the offline-mode caveat)

**JSON** (`--json`) — full findings + per-file records with all mappings, for
ingestion into other tooling (GhostHive blackboard, findings DBs, diffing
between builds).

## Control-mapping cheat sheet

| Theme | CWE | ATT&CK | OWASP | NIST 800-53 | CIS v8 |
|---|---|---|---|---|---|
| Missing/invalid signatures | CWE-347, CWE-494 | T1553.002, T1554, T1036.001 | A08:2021 | SI-7, CM-14, CM-5 | 2.3, 10.5 |
| Chain/certificate problems | CWE-295, CWE-298 | T1553.002 | A08:2021 | SI-7, IA-5(2) | 2.3 |
| Weak digest | CWE-328 | T1553.002 | A02:2021 | SC-13 | 2.3 |
| Writable binaries/dirs | CWE-276, CWE-427 | T1574.001/.005/.007/.010 | A01:2021 | AC-3, AC-6, CM-5 | 3.3 |

## Notes & limitations

- Catalog-signed Microsoft OS files verify correctly **only** in Windows mode.
- Offline digest/signer/timestamp extraction is OID-based heuristic analysis
  of the PKCS#7 blob — reliable in practice, but validity is never claimed.
- Script signature detection outside Windows only checks for an embedded
  `# SIG # Begin signature block` marker in PowerShell files.
- MSI/MSP/APPX signature validation is performed in Windows mode; offline mode
  records them as unverifiable installers.
- The tool reads files and ACLs only — it never modifies the target.

## Versioning

Suite convention: no git — meaningful changes bump the version in the header
and get a zip snapshot alongside the working file (`gh0stsign-2.0.zip`).

---

*Findings require validation in engagement context. Use only on systems you
are authorized to assess (rules-of-engagement coverage or your own lab).*# gh0stsign
Thick Client Digital Signature Checking Tool

## Overview

`gh0stsign` is a command-line tool designed to check the digital signatures of files within a specified directory or a single file. It helps users identify whether files have valid digital signatures or are unsigned. The tool is cross-platform and can be used on both Windows and Linux operating systems.

## Requirements
- For Windows: Ensure you have the `sigcheck` utility available in your system's PATH. You can download it from Sysinternals Suite: https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
- For Linux: Ensure you have the `codesign` utility available in your system's PATH. This utility is typically included in the `osslsigncode` package. Install it using your package manager if needed.


## Features

- Check the digital signatures of individual files or all files within a directory.
- Cross-platform support for both Windows and Linux.
- Option to enable verbose mode to display detailed verification information.
- Generate a detailed findings report containing verification results.
- Display detailed findings including signature status, verification output, signer, digest algorithm, and timestamp (on Windows).

## Getting Started

1. Clone this repository or download the `gh0stsign.py` script.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Run the script using the command: `python gh0stsign.py`

## Usage

1. Run the script: `python gh0stsign.py`
2. Enter the path to a single file or a directory when prompted.
3. Choose whether to enable verbose mode to see detailed verification information (optional).
4. The tool will display the findings and generate a detailed findings report.

## Example

To check the digital signatures of a single file:
python gh0stsign.py /path/to/single/file.exe - Windows
python3 gh0stsign.py /path/to/single/file.exe - Linux

To check the digital signatures of files within a directory:
python gh0stsign.py /path/to/directory/ - Windows
python3 gh0stsign.py /path/to/directory/ - Linux


## Report

After running the tool, a detailed findings report will be generated. The report will include information about each file's status, verification output, and a summary of signed and unsigned files.

The default report filename is `gh0stsign_findings_report.txt`, but you can provide a custom name when prompted.

## Author

Created by: gh0stsh3ll5619
GitHub: gh0stsh3ll5619


## License

This project is licensed under the [MIT License](LICENSE).
