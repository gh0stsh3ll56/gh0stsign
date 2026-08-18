#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gh0stSign v2.0.0 -- code-signing & binary-integrity validation
Ghost Ops Security / Kill Chain Replay -- Authorized Use Only

Application-security assessment of installed software: walks an application
directory (or single file) and validates the code-signing and file-permission
posture of every executable artifact.

Checks
  GS-01  Tampered signature (Authenticode hash mismatch)          CRITICAL
  GS-02  Unsigned kernel driver (.sys / native subsystem)         HIGH
  GS-03  Unsigned executable / library                            HIGH
         (escalated to CRITICAL when also writable by low-priv users)
  GS-04  Untrusted / self-signed signing chain                    HIGH
  GS-05  Binary writable by low-privileged users                  HIGH
  GS-06  Install directory writable by low-privileged users       HIGH
         (DLL planting / search-order hijack surface)
  GS-07  Expired or not-yet-valid signing certificate             MEDIUM
  GS-08  Weak signature digest (MD5 / SHA-1)                      MEDIUM
  GS-09  Unsigned script (.ps1/.psm1/.vbs/.js/...)                MEDIUM
  GS-10  Signature not timestamped (dies with the certificate)    LOW
  GS-11  World/group-writable executable (POSIX)                  HIGH

Platforms
  Windows  -- full verification via PowerShell Get-AuthenticodeSignature
              (validity, chain, catalog signatures) + Get-Acl DACL review.
              No third-party modules required (no pywin32, no sigcheck).
  Linux/…  -- offline mode: parses the PE Authenticode certificate table
              directly (presence, digest algorithm, signer CNs, timestamp
              countersignature) for Windows binaries mounted/copied to the
              assessment box. Presence != validity; the report says which
              mode produced each result.

Every finding is mapped to CWE, MITRE ATT&CK, OWASP Top 10, NIST 800-53 and
CIS Controls v8. Output: tabbed CLI summary, Markdown report, optional JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat as statmod
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

VERSION = "2.0.0"
IS_WINDOWS = os.name == "nt"

# ------------------------------------------------------------------ targets
PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi",
           ".mui", ".ax", ".acm", ".tsp", ".node", ".pyd", ".winmd"}
INSTALLER_EXTS = {".msi", ".msp", ".mst", ".cab", ".appx", ".msix"}
SCRIPT_EXTS = {".ps1", ".psm1", ".psd1", ".vbs", ".js", ".wsf", ".jse", ".vbe"}
CODE_EXTS = PE_EXTS | INSTALLER_EXTS | SCRIPT_EXTS

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# low-privileged identities whose write access on program files is a finding
LOWPRIV_RE = re.compile(
    r"(Everyone|BUILTIN\\Users|\\Users$|Authenticated Users|INTERACTIVE|"
    r"Domain Users|ANONYMOUS|Guests)", re.I)
WRITE_RIGHTS_RE = re.compile(
    r"(FullControl|Modify|Write(?!Attributes)|CreateFiles|AppendData|"
    r"ChangePermissions|TakeOwnership|Delete\b|268435456|1073741824|2032127|"
    r"197055|1245631)", )

# ---------------------------------------------------------------- controls
# check id -> (title, severity, cwe, mitre, owasp, nist 800-53, cis v8,
#              why it matters, remediation)
CONTROLS = {
    "GS-01": ("Tampered code signature (hash mismatch)", "CRITICAL",
              "CWE-494 Download of Code Without Integrity Check",
              "T1554 Compromise Host Software Binary; T1036.001 Invalid Code Signature",
              "A08:2021 Software and Data Integrity Failures",
              "SI-7 Software Integrity; IR-4",
              "CIS 10.5, 2.3",
              "The file's content no longer matches its embedded signature -- the binary "
              "was modified after signing. This is the signature a defender relies on to "
              "detect exactly this condition; treat as a potential supply-chain or "
              "on-host implant until proven otherwise.",
              "Quarantine and compare against a known-good copy from the vendor; "
              "investigate how the file was modified; restore from trusted media."),
    "GS-02": ("Unsigned kernel driver", "HIGH",
              "CWE-347 Improper Verification of Cryptographic Signature",
              "T1068 Exploitation for Privilege Escalation; T1553.002 Code Signing",
              "A08:2021 Software and Data Integrity Failures",
              "SI-7; CM-14 Signed Components",
              "CIS 2.3, 10.5",
              "Kernel drivers execute at the highest privilege. An unsigned driver "
              "either predates signing enforcement, ships with test-signing expected, "
              "or is loaded via a bypass -- all weaken the kernel trust boundary "
              "(BYOVD-adjacent risk).",
              "Require WHQL/EV-signed drivers; enable and verify Driver Signature "
              "Enforcement and HVCI/WDAC policies."),
    "GS-03": ("Unsigned executable / library", "HIGH",
              "CWE-347 Improper Verification of Cryptographic Signature",
              "T1553.002 Subvert Trust Controls: Code Signing; T1574 Hijack Execution Flow",
              "A08:2021 Software and Data Integrity Failures",
              "SI-7(15) Code Authentication; CM-5",
              "CIS 2.3 (allowlisting), 10.5",
              "Unsigned product binaries cannot be distinguished from attacker-planted "
              "ones by users, EDR allowlisting, or WDAC/AppLocker publisher rules. "
              "Integrity of the install cannot be attested.",
              "Sign all shipped PE files with an EV/OV certificate and a "
              "timestamp; enforce publisher-based application control."),
    "GS-04": ("Untrusted or self-signed signing chain", "HIGH",
              "CWE-295 Improper Certificate Validation",
              "T1553.002 Code Signing (illegitimate certificates)",
              "A08:2021 Software and Data Integrity Failures",
              "SI-7; IA-5(2) PKI-based authentication",
              "CIS 2.3",
              "A signature that does not chain to a trusted root gives no integrity or "
              "origin guarantee -- self-signed certificates are trivially forged by "
              "malware to appear 'signed'.",
              "Re-sign with a certificate from a trusted CA; remove ad-hoc/self-signed "
              "certificates from production builds."),
    "GS-05": ("Binary writable by low-privileged users", "HIGH",
              "CWE-276 Incorrect Default Permissions",
              "T1574.005/010 File Permissions Weakness (installer/services)",
              "A01:2021 Broken Access Control",
              "AC-3, AC-6 Least Privilege; CM-5(6)",
              "CIS 3.3 Configure Data Access Control Lists",
              "Any local user can replace the binary; when it is later executed by an "
              "administrator, a service, or a scheduled task, this is direct privilege "
              "escalation and persistence.",
              "Restrict write/modify on program binaries to Administrators/"
              "TrustedInstaller; audit service binaries and their DACLs at install time."),
    "GS-06": ("Install directory writable by low-privileged users", "HIGH",
              "CWE-427 Uncontrolled Search Path Element",
              "T1574.001 DLL Search Order Hijacking; T1574.007 PATH Interception",
              "A01:2021 Broken Access Control",
              "AC-6; CM-5",
              "CIS 3.3",
              "A user-writable application directory lets an attacker plant DLLs or "
              "executables that the application loads by name (search-order hijack), "
              "hijacking any higher-privileged process that starts from it.",
              "Install under %ProgramFiles% with inherited restrictive ACLs; never "
              "grant Users/Everyone create/write on application directories."),
    "GS-07": ("Expired or not-yet-valid signing certificate", "MEDIUM",
              "CWE-298 Improper Validation of Certificate Expiration",
              "T1553.002 Code Signing",
              "A08:2021 Software and Data Integrity Failures",
              "SI-7; IA-5(2)",
              "CIS 2.3",
              "Without a valid timestamp, a signature made with a now-expired "
              "certificate no longer validates, and platforms may treat the file as "
              "unsigned; it also signals an unmaintained signing pipeline.",
              "Re-sign with a current certificate and RFC-3161 timestamp so validity "
              "survives certificate expiry."),
    "GS-08": ("Weak signature digest algorithm (MD5/SHA-1)", "MEDIUM",
              "CWE-328 Use of Weak Hash",
              "T1553.002 Code Signing",
              "A02:2021 Cryptographic Failures",
              "SC-13 Cryptographic Protection; SI-7",
              "CIS 2.3",
              "MD5 and SHA-1 are collision-broken: an attacker can craft a different "
              "binary with the same digest, making the signature meaningless. Windows "
              "distrusts SHA-1 code signatures in most contexts.",
              "Re-sign (or dual-sign) all artifacts with SHA-256 or stronger."),
    "GS-09": ("Unsigned script", "MEDIUM",
              "CWE-347 Improper Verification of Cryptographic Signature",
              "T1059 Command and Scripting Interpreter",
              "A08:2021 Software and Data Integrity Failures",
              "SI-7(15); CM-14",
              "CIS 2.3, 2.7",
              "Unsigned PowerShell/VBS/JS shipped with the product cannot be protected "
              "by execution policies (AllSigned) or WDAC script enforcement and is a "
              "soft target for tampering.",
              "Authenticode-sign shipped scripts; run with AllSigned/ConstrainedLanguage "
              "where feasible."),
    "GS-10": ("Signature missing timestamp countersignature", "LOW",
              "CWE-347 Improper Verification of Cryptographic Signature",
              "T1553.002 Code Signing",
              "A08:2021 Software and Data Integrity Failures",
              "SI-7",
              "CIS 2.3",
              "Without an RFC-3161/Authenticode timestamp the signature becomes invalid "
              "the day the signing certificate expires or is revoked.",
              "Always countersign with a timestamp service at build time."),
    "GS-11": ("World/group-writable executable (POSIX)", "HIGH",
              "CWE-276 Incorrect Default Permissions",
              "T1574 Hijack Execution Flow",
              "A01:2021 Broken Access Control",
              "AC-3, AC-6",
              "CIS 3.3",
              "Any local user (or group member) can replace the executable content, "
              "escalating to whichever principal runs it.",
              "chmod o-w/g-w on executables; verify packaging umask and installer "
              "post-install permissions."),
}


# =================================================================== PE parse
def parse_pe(path: str) -> dict:
    """Minimal, dependency-free PE reader: architecture, driver-ness and the
    Authenticode certificate table (data directory #4)."""
    info = {"is_pe": False, "arch": "", "is_driver": False,
            "has_embedded_sig": False, "sig_blob": b"", "error": ""}
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return info
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            fh.seek(e_lfanew)
            if fh.read(4) != b"PE\0\0":
                return info
            coff = fh.read(20)
            if len(coff) < 20:
                return info
            machine, _nsec, _ts, _psym, _nsym, opt_size, chars = \
                struct.unpack("<HHIIIHH", coff)
            info["is_pe"] = True
            info["arch"] = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64",
                            0x1C4: "arm"}.get(machine, hex(machine))
            if opt_size == 0:
                return info
            opt = fh.read(opt_size)
            magic = struct.unpack_from("<H", opt, 0)[0]
            if magic == 0x10B:      # PE32
                dd_off, subsys_off = 96, 68
            elif magic == 0x20B:    # PE32+
                dd_off, subsys_off = 112, 68
            else:
                return info
            if len(opt) >= subsys_off + 2:
                subsystem = struct.unpack_from("<H", opt, subsys_off)[0]
                info["is_driver"] = subsystem == 1  # IMAGE_SUBSYSTEM_NATIVE
            # data directory entry 4 = certificate table (file offset, size)
            cert_entry = dd_off + 4 * 8
            if len(opt) >= cert_entry + 8:
                cert_off, cert_size = struct.unpack_from("<II", opt, cert_entry)
                if cert_off and cert_size:
                    info["has_embedded_sig"] = True
                    fh.seek(cert_off)
                    info["sig_blob"] = fh.read(min(cert_size, 4_000_000))
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
    return info


# ASN.1 OID byte patterns inside the PKCS#7 blob (heuristic but reliable:
# these exact TLV encodings only appear as algorithm/attribute identifiers)
OID_SHA256 = bytes.fromhex("0609608648016503040201")
OID_SHA384 = bytes.fromhex("0609608648016503040202")
OID_SHA512 = bytes.fromhex("0609608648016503040203")
OID_SHA1 = bytes.fromhex("06052b0e03021a")
OID_MD5 = bytes.fromhex("06082a864886f70d0205")
OID_COUNTERSIG = bytes.fromhex("06092a864886f70d010906")       # PKCS#9 counterSignature
OID_RFC3161 = bytes.fromhex("060a2b0601040182370303ac")[:11]   # 1.3.6.1.4.1.311.3.3.1
OID_CN = bytes.fromhex("0603550403")


def analyze_sig_blob(blob: bytes) -> dict:
    """Offline analysis of an Authenticode PKCS#7 blob: digest algorithm,
    signer common names, timestamp presence."""
    out = {"digest": "", "signers": [], "timestamped": False}
    if not blob:
        return out
    if OID_MD5 in blob:
        out["digest"] = "MD5"
    elif OID_SHA1 in blob and not any(o in blob for o in (OID_SHA256, OID_SHA384, OID_SHA512)):
        out["digest"] = "SHA1"
    elif OID_SHA256 in blob:
        out["digest"] = "SHA256"
    elif OID_SHA384 in blob:
        out["digest"] = "SHA384"
    elif OID_SHA512 in blob:
        out["digest"] = "SHA512"
    out["timestamped"] = OID_COUNTERSIG in blob or OID_RFC3161 in blob
    # commonName strings: OID 2.5.4.3 followed by a Printable/UTF8String TLV
    names = []
    i = 0
    while True:
        i = blob.find(OID_CN, i)
        if i < 0 or len(names) > 12:
            break
        j = i + len(OID_CN)
        if j + 2 <= len(blob) and blob[j] in (0x0C, 0x13, 0x14, 0x1E):  # UTF8/Printable/T61/BMP
            ln = blob[j + 1]
            if ln < 0x80 and j + 2 + ln <= len(blob):
                try:
                    s = blob[j + 2:j + 2 + ln].decode("utf-8", "replace").strip()
                    if s and s not in names:
                        names.append(s)
                except Exception:
                    pass
        i = j
    out["signers"] = names
    return out


# ============================================================== windows mode
def _ps(script: str, timeout: int = 900) -> str:
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                        "-ExecutionPolicy", "Bypass", "-Command", script],
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout


def _ps_json(script: str) -> list:
    out = _ps(script)
    if not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def win_authenticode(paths: list[str]) -> dict[str, dict]:
    """Batch Get-AuthenticodeSignature via a temp list file (avoids command-
    line length limits). Verifies embedded AND catalog signatures."""
    results: dict[str, dict] = {}
    if not paths:
        return results
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8-sig") as fh:
        fh.write("\n".join(paths))
        listfile = fh.name
    script = f"""
$ErrorActionPreference='SilentlyContinue'
$out = foreach ($p in (Get-Content -LiteralPath '{listfile}')) {{
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $c = $s.SignerCertificate
  [pscustomobject]@{{
    Path=$p; Status=[string]$s.Status; Message=[string]$s.StatusMessage
    Type=[string]$s.SignatureType
    Signer=$(if($c){{$c.Subject}}else{{''}})
    Issuer=$(if($c){{$c.Issuer}}else{{''}})
    NotBefore=$(if($c){{$c.NotBefore.ToUniversalTime().ToString('yyyy-MM-dd')}}else{{''}})
    NotAfter=$(if($c){{$c.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')}}else{{''}})
    SelfSigned=$(if($c){{$c.Subject -eq $c.Issuer}}else{{$false}})
    Timestamped=$([bool]$s.TimeStamperCertificate)
    CertExpired=$(if($c){{$c.NotAfter -lt (Get-Date)}}else{{$false}})
    CertNotYetValid=$(if($c){{$c.NotBefore -gt (Get-Date)}}else{{$false}})
  }}
}}
$out | ConvertTo-Json -Depth 3
"""
    try:
        for row in _ps_json(script):
            if row.get("Path"):
                results[row["Path"]] = row
    finally:
        try:
            os.unlink(listfile)
        except OSError:
            pass
    return results


def win_acl(paths: list[str]) -> dict[str, list[str]]:
    """Batch Get-Acl: returns, per path, the Allow ACEs that grant write-class
    rights to low-privileged identities."""
    results: dict[str, list[str]] = {}
    if not paths:
        return results
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8-sig") as fh:
        fh.write("\n".join(paths))
        listfile = fh.name
    script = f"""
$ErrorActionPreference='SilentlyContinue'
$out = foreach ($p in (Get-Content -LiteralPath '{listfile}')) {{
  $acl = Get-Acl -LiteralPath $p
  $aces = foreach ($a in $acl.Access) {{
    if ($a.AccessControlType -eq 'Allow') {{
      '{{0}} : {{1}}' -f $a.IdentityReference, $a.FileSystemRights }} }}
  [pscustomobject]@{{ Path=$p; Aces=@($aces) }}
}}
$out | ConvertTo-Json -Depth 3
"""
    try:
        for row in _ps_json(script):
            path = row.get("Path", "")
            bad = []
            for ace in row.get("Aces") or []:
                ident, _, rights = ace.partition(" : ")
                if LOWPRIV_RE.search(ident) and WRITE_RIGHTS_RE.search(rights):
                    bad.append(ace)
            if path:
                results[path] = bad
    finally:
        try:
            os.unlink(listfile)
        except OSError:
            pass
    return results


# ================================================================== scanner
def sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def posix_writability(path: str) -> list[str]:
    try:
        st = os.stat(path)
    except OSError:
        return []
    out = []
    if st.st_mode & statmod.S_IWOTH:
        out.append("world-writable (o+w)")
    if st.st_mode & statmod.S_IWGRP:
        out.append(f"group-writable (gid {st.st_gid})")
    return out


def collect_files(root: str, all_files: bool, max_files: int) -> list[str]:
    if os.path.isfile(root):
        return [root]
    hits = []
    for r, _dirs, files in os.walk(root):
        for f in files:
            if all_files or os.path.splitext(f)[1].lower() in CODE_EXTS:
                hits.append(os.path.join(r, f))
                if len(hits) >= max_files:
                    return hits
    return hits


def scan(root: str, all_files: bool, check_acl: bool, max_files: int,
         verbose: bool) -> dict:
    files = collect_files(root, all_files, max_files)
    mode = "windows-verify" if IS_WINDOWS else "offline-pe-analysis"
    print(f"[*] {len(files)} candidate files under {root} (mode: {mode})")

    sig_results: dict[str, dict] = {}
    if IS_WINDOWS:
        verifiable = [f for f in files if os.path.splitext(f)[1].lower()
                      in PE_EXTS | INSTALLER_EXTS | SCRIPT_EXTS]
        for i in range(0, len(verifiable), 200):
            chunk = verifiable[i:i + 200]
            sig_results.update(win_authenticode(chunk))
            print(f"[*] authenticode: {min(i+200, len(verifiable))}/{len(verifiable)}")

    records = []            # one per file
    findings = []           # one per (check, file)
    dirs_seen: set[str] = set()

    def add_finding(check: str, path: str, evidence: str, severity: str = ""):
        title, sev, cwe, mitre, owasp, nist, cis, why, fix = CONTROLS[check]
        findings.append({"check": check, "title": title,
                         "severity": severity or sev, "file": path,
                         "evidence": evidence, "cwe": cwe, "mitre": mitre,
                         "owasp": owasp, "nist": nist, "cis": cis,
                         "why": why, "remediation": fix})

    for path in files:
        ext = os.path.splitext(path)[1].lower()
        is_pe_ext = ext in PE_EXTS
        rec = {"file": path, "ext": ext, "size": 0, "arch": "", "driver": False,
               "sig_status": "unknown", "sig_source": mode, "signer": "",
               "issuer": "", "digest": "", "timestamped": None,
               "not_after": "", "writable_by": [], "sha256": "", "issues": []}
        try:
            rec["size"] = os.path.getsize(path)
        except OSError:
            continue

        pe = parse_pe(path) if is_pe_ext else {"is_pe": False, "is_driver": False,
                                               "has_embedded_sig": False, "sig_blob": b""}
        rec["driver"] = pe["is_driver"] or ext == ".sys"
        rec["arch"] = pe.get("arch", "")

        # ---- signature verdict -------------------------------------------
        if IS_WINDOWS and path in sig_results:
            s = sig_results[path]
            status = s.get("Status", "")
            rec["sig_status"] = status
            rec["signer"] = s.get("Signer", "")
            rec["issuer"] = s.get("Issuer", "")
            rec["not_after"] = s.get("NotAfter", "")
            rec["timestamped"] = bool(s.get("Timestamped"))
            blobinfo = analyze_sig_blob(pe["sig_blob"])
            rec["digest"] = blobinfo["digest"]
            if status == "HashMismatch":
                add_finding("GS-01", path, f"Get-AuthenticodeSignature: {s.get('Message','')}")
            elif status == "NotSigned":
                rec["sig_status"] = "NotSigned"
            elif status in ("UnknownError", "NotTrusted") or s.get("SelfSigned"):
                add_finding("GS-04", path,
                            f"status={status} self_signed={bool(s.get('SelfSigned'))} "
                            f"signer={rec['signer'][:120]}")
            if s.get("CertExpired") or s.get("CertNotYetValid"):
                add_finding("GS-07", path,
                            f"cert validity {s.get('NotBefore','?')}..{s.get('NotAfter','?')} "
                            f"(expired={bool(s.get('CertExpired'))})")
            if status == "Valid" and not rec["timestamped"]:
                add_finding("GS-10", path, "signature valid but no timestamp countersignature")
        elif is_pe_ext and pe["is_pe"]:
            # offline: presence + blob analysis (validity cannot be proven here)
            if pe["has_embedded_sig"]:
                b = analyze_sig_blob(pe["sig_blob"])
                rec["sig_status"] = "SignedEmbedded(unverified)"
                rec["digest"] = b["digest"]
                rec["timestamped"] = b["timestamped"]
                rec["signer"] = "; ".join(b["signers"][:4])
                if not b["timestamped"]:
                    add_finding("GS-10", path, "embedded signature carries no timestamp OID")
            else:
                rec["sig_status"] = "NotSigned(no cert table)"
        elif is_pe_ext and not pe["is_pe"]:
            rec["sig_status"] = "not-a-PE"
        elif ext in SCRIPT_EXTS and not IS_WINDOWS:
            try:
                tail = open(path, "rb").read()[-4096:]
                rec["sig_status"] = ("SignedEmbedded(unverified)"
                                     if b"SIG # Begin signature block" in tail
                                     else "NotSigned")
            except OSError:
                rec["sig_status"] = "unreadable"

        # ---- unsigned findings -------------------------------------------
        unsigned = rec["sig_status"].startswith("NotSigned")
        if unsigned and rec["driver"]:
            add_finding("GS-02", path, f"unsigned driver ({rec['arch']})")
        elif unsigned and (is_pe_ext or ext in INSTALLER_EXTS) and rec["sig_status"] != "not-a-PE":
            add_finding("GS-03", path, f"no Authenticode signature ({ext}, {rec['arch'] or 'n/a'})")
        elif unsigned and ext in SCRIPT_EXTS:
            add_finding("GS-09", path, f"unsigned {ext} script")
        if rec["digest"] in ("MD5", "SHA1"):
            add_finding("GS-08", path, f"signature file-digest algorithm: {rec['digest']}")

        # ---- writability ---------------------------------------------------
        if not IS_WINDOWS:
            w = posix_writability(path)
            rec["writable_by"] = w
            if w and (is_pe_ext or ext in SCRIPT_EXTS or os.access(path, os.X_OK)):
                # group-writable alone is a hygiene issue; world-writable is the
                # code-planting path and drives the CRITICAL escalation below
                world = any("world" in x for x in w)
                add_finding("GS-11", path, "; ".join(w),
                            severity="HIGH" if world else "MEDIUM")
        if unsigned:
            rec["sha256"] = sha256(path)
        dirs_seen.add(os.path.dirname(path))
        records.append(rec)
        if verbose:
            print(f"    {rec['sig_status']:<28} {path}")

    # ---- Windows DACL review (files + their directories) -------------------
    if IS_WINDOWS and check_acl:
        acl_targets = [r["file"] for r in records] + sorted(dirs_seen)
        acls: dict[str, list[str]] = {}
        for i in range(0, len(acl_targets), 300):
            acls.update(win_acl(acl_targets[i:i + 300]))
            print(f"[*] acl review: {min(i+300, len(acl_targets))}/{len(acl_targets)}")
        for r in records:
            bad = acls.get(r["file"]) or []
            r["writable_by"] = bad
            if bad:
                add_finding("GS-05", r["file"], " | ".join(bad[:4]))
        for d in sorted(dirs_seen):
            bad = acls.get(d) or []
            if bad:
                add_finding("GS-06", d, " | ".join(bad[:4]))

    # escalation: unsigned AND writable by low-priv = direct code-planting
    # (Windows DACL hits always qualify; POSIX only when world-writable)
    writable_files = {f["file"] for f in findings
                      if f["check"] == "GS-05"
                      or (f["check"] == "GS-11" and "world" in f["evidence"])}
    for f in findings:
        if f["check"] in ("GS-02", "GS-03") and f["file"] in writable_files:
            f["severity"] = "CRITICAL"
            f["evidence"] += "  [ESCALATED: also writable by low-privileged users]"

    findings.sort(key=lambda f: (SEV_ORDER.index(f["severity"]), f["check"], f["file"]))
    return {"root": root, "mode": mode, "files": records, "findings": findings}


# =================================================================== output
def table(headers: list[str], rows: list[list[str]], indent: str = "  ") -> str:
    if not rows:
        return indent + "(none)"
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows))
              for i, h in enumerate(headers)]
    def fmt(row):
        return indent + "  ".join(str(c).ljust(w) for c, w in zip(row, widths)).rstrip()
    sep = indent + "  ".join("-" * w for w in widths)
    return "\n".join([fmt(headers), sep] + [fmt(r) for r in rows])


def cli_report(result: dict, top: int = 25) -> None:
    recs, finds = result["files"], result["findings"]
    signed = sum(1 for r in recs if r["sig_status"].startswith(("Valid", "SignedEmbedded")))
    unsigned = sum(1 for r in recs if r["sig_status"].startswith("NotSigned"))
    sev_counts = {s: sum(1 for f in finds if f["severity"] == s) for s in SEV_ORDER}

    print("\n[ SUMMARY ]")
    print(table(["metric", "value"], [
        ["scan mode", result["mode"]],
        ["files examined", len(recs)],
        ["signed", signed],
        ["unsigned", unsigned],
        ["unsigned drivers", sum(1 for r in recs if r["driver"]
                                 and r["sig_status"].startswith("NotSigned"))],
        ["writable by low-priv", sum(1 for r in recs if r["writable_by"])],
        ["total findings", len(finds)],
    ]))

    print("\n[ FINDINGS BY CHECK ]")
    agg: dict[tuple, int] = {}
    for f in finds:
        agg[(f["severity"], f["check"], f["title"])] = \
            agg.get((f["severity"], f["check"], f["title"]), 0) + 1
    print(table(["sev", "check", "title", "count"],
                [[s, c, t, n] for (s, c, t), n in
                 sorted(agg.items(), key=lambda kv: (SEV_ORDER.index(kv[0][0]), kv[0][1]))]))

    print(f"\n[ TOP FINDINGS (first {top}) ]")
    print(table(["sev", "check", "file", "evidence"],
                [[f["severity"], f["check"],
                  (f["file"] if len(f["file"]) <= 70 else "..." + f["file"][-67:]),
                  f["evidence"][:60]] for f in finds[:top]]))

    print("\n[ PUBLISHERS ]")
    pubs: dict[str, int] = {}
    for r in recs:
        if r["signer"]:
            cn = re.search(r"CN=([^,]+)", r["signer"])
            pubs[cn.group(1) if cn else r["signer"][:60]] = \
                pubs.get(cn.group(1) if cn else r["signer"][:60], 0) + 1
    print(table(["publisher", "files"],
                sorted(pubs.items(), key=lambda kv: -kv[1])[:10] or []))


def md_report(result: dict, out_path: str) -> str:
    recs, finds = result["files"], result["findings"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    signed = sum(1 for r in recs if r["sig_status"].startswith(("Valid", "SignedEmbedded")))
    unsigned = sum(1 for r in recs if r["sig_status"].startswith("NotSigned"))
    sev_counts = {s: sum(1 for f in finds if f["severity"] == s) for s in SEV_ORDER}
    worst = next((s for s in SEV_ORDER if sev_counts[s]), "none")

    L = []
    L.append(f"# Gh0stSign Code-Signing Assessment Report")
    L.append("")
    L.append(f"| | |\n|---|---|")
    L.append(f"| Tool | Gh0stSign v{VERSION} (Ghost Ops Security — Authorized Use Only) |")
    L.append(f"| Date | {now} |")
    L.append(f"| Target | `{result['root']}` |")
    L.append(f"| Host / platform | {platform.node()} / {platform.platform()} |")
    L.append(f"| Scan mode | {result['mode']} |")
    L.append("")
    L.append("## Executive summary")
    L.append("")
    L.append(f"{len(recs)} executable artifacts were assessed for code-signing and "
             f"file-permission integrity. **{unsigned} are unsigned** and {signed} carry "
             f"a signature. {len(finds)} findings were raised; highest severity: "
             f"**{worst}**. Unsigned or user-writable binaries defeat application "
             f"allowlisting, EDR trust decisions, and update integrity — the "
             f"software-and-data-integrity failures class (OWASP A08:2021).")
    L.append("")
    L.append("### Findings by severity")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for s in SEV_ORDER:
        L.append(f"| {s} | {sev_counts[s]} |")
    L.append("")
    if result["mode"] != "windows-verify":
        L.append("> **Scan-mode caveat:** this run used offline PE analysis on a "
                 "non-Windows host. It proves signature *presence*, digest algorithm, "
                 "signer names and timestamping, but cannot validate trust chains, "
                 "revocation, or **catalog signatures** (Microsoft OS files are often "
                 "catalog-signed and will show as `NotSigned(no cert table)` here). "
                 "Re-run on Windows for authoritative verdicts.")
        L.append("")

    L.append("## Detailed findings")
    by_check: dict[str, list[dict]] = {}
    for f in finds:
        by_check.setdefault(f["check"], []).append(f)
    for check in sorted(by_check, key=lambda c: SEV_ORDER.index(by_check[c][0]["severity"])):
        fl = by_check[check]
        c = CONTROLS[check]
        sevs = sorted({f["severity"] for f in fl}, key=SEV_ORDER.index)
        L.append("")
        L.append(f"### {check}: {c[0]} — {'/'.join(sevs)} ({len(fl)} affected)")
        L.append("")
        L.append("| Control mapping | Value |")
        L.append("|---|---|")
        L.append(f"| CWE | {c[2]} |")
        L.append(f"| MITRE ATT&CK | {c[3]} |")
        L.append(f"| OWASP | {c[4]} |")
        L.append(f"| NIST 800-53 | {c[5]} |")
        L.append(f"| CIS v8 | {c[6]} |")
        L.append("")
        L.append(f"**Risk.** {c[7]}")
        L.append("")
        L.append(f"**Remediation.** {c[8]}")
        L.append("")
        L.append("**Affected files / evidence:**")
        L.append("")
        L.append("| Severity | File | Evidence |")
        L.append("|---|---|---|")
        for f in fl[:200]:
            L.append(f"| {f['severity']} | `{f['file']}` | {f['evidence'][:200]} |")
        if len(fl) > 200:
            L.append(f"| | ... | {len(fl)-200} more (see JSON output) |")

    L.append("")
    L.append("## Signed-file inventory")
    L.append("")
    L.append("| File | Status | Signer | Digest | Timestamped | Cert expiry |")
    L.append("|---|---|---|---|---|---|")
    for r in recs:
        if not r["sig_status"].startswith(("Valid", "SignedEmbedded")):
            continue
        L.append(f"| `{os.path.basename(r['file'])}` | {r['sig_status']} | "
                 f"{(r['signer'] or '')[:60]} | {r['digest'] or '?'} | "
                 f"{'yes' if r['timestamped'] else 'NO' if r['timestamped'] is False else '?'} | "
                 f"{r['not_after'] or '-'} |")
    L.append("")
    L.append("## Unsigned-file inventory (SHA-256 evidence)")
    L.append("")
    L.append("| File | Type | Arch | SHA-256 |")
    L.append("|---|---|---|---|")
    for r in recs:
        if r["sig_status"].startswith("NotSigned"):
            L.append(f"| `{r['file']}` | {r['ext']}{' driver' if r['driver'] else ''} | "
                     f"{r['arch'] or '-'} | `{r['sha256'] or '-'}` |")
    L.append("")
    L.append("## Methodology & limitations")
    L.append("")
    L.append("- **Windows mode:** `Get-AuthenticodeSignature` (embedded **and** catalog "
             "signatures, full chain validation) + `Get-Acl` DACL review for write-class "
             "rights granted to Everyone / BUILTIN\\Users / Authenticated Users / "
             "INTERACTIVE / Domain Users / Guests, on binaries and their directories.")
    L.append("- **Offline mode:** direct parse of the PE certificate table "
             "(IMAGE_DIRECTORY_ENTRY_SECURITY) with ASN.1 OID analysis for digest "
             "algorithm, signer CNs and timestamp countersignature. Presence ≠ validity.")
    L.append("- Severity escalation: unsigned binaries that are also writable by "
             "low-privileged users are raised to CRITICAL (direct code-planting path).")
    L.append("- References: MITRE ATT&CK T1553.002 / T1574; OWASP A08:2021; "
             "NIST SP 800-53r5 SI-7/CM-14; CIS Controls v8; Microsoft Authenticode PE "
             "signature format specification.")
    L.append("")
    L.append(f"*Generated by Gh0stSign v{VERSION} — findings require validation in "
             f"context; authorized engagements only.*")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    return out_path


BANNER = rf"""
   ________  ______        __  _____ _
  / ____/ / / / __ \______/ /_/ ___/(_)___ _____
 / / __/ /_/ / / / / ___/ __/\__ \/ / __ `/ __ \
/ /_/ / __  / /_/ (__  ) /_ ___/ / / /_/ / / / /
\____/_/ /_/\____/____/\__//____/_/\__, /_/ /_/
                                  /____/  v{VERSION}
  code-signing & binary-integrity validation -- Authorized Use Only
"""


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="gh0stsign",
        description="Validate code signatures + binary/file-permission integrity "
                    "of an application install (appsec pentest support).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  gh0stsign.py "C:\\Program Files\\TargetApp"                 # full Windows verify
  gh0stsign.py "C:\\Program Files\\TargetApp" -r app.md --json app.json
  gh0stsign.py /mnt/target/Program\\ Files/App               # offline PE mode (Kali)
  gh0stsign.py app_dir --all-files --fail-on HIGH            # CI gate: exit 2 if >=HIGH
""")
    ap.add_argument("path", nargs="?", help="file or directory to assess")
    ap.add_argument("-r", "--report", default="gh0stsign_report.md",
                    help="Markdown report path (default gh0stsign_report.md)")
    ap.add_argument("--json", default="", help="also write findings JSON here")
    ap.add_argument("-v", "--verbose", action="store_true", help="print each file verdict")
    ap.add_argument("--all-files", action="store_true",
                    help="examine every file, not just executable/script extensions")
    ap.add_argument("--no-acl", action="store_true", help="skip the Windows DACL review")
    ap.add_argument("--max-files", type=int, default=20000)
    ap.add_argument("--top", type=int, default=25, help="findings shown in the CLI table")
    ap.add_argument("--fail-on", choices=SEV_ORDER, default="",
                    help="exit 2 if any finding at/above this severity (CI usage)")
    args = ap.parse_args()

    print(BANNER)
    path = args.path or input("Path to the file or application directory: ").strip().strip('"')
    if not path or not os.path.exists(path):
        print("[!] path not found")
        return 1

    result = scan(path, args.all_files, not args.no_acl, args.max_files, args.verbose)
    cli_report(result, args.top)
    md = md_report(result, args.report)
    print(f"\n[+] Markdown report: {md}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"tool": f"gh0stsign/{VERSION}",
                       "generated": datetime.now(timezone.utc).isoformat(),
                       "target": result["root"], "mode": result["mode"],
                       "findings": result["findings"], "files": result["files"]},
                      fh, indent=1, default=str)
        print(f"[+] JSON findings: {args.json}")

    if args.fail_on:
        threshold = SEV_ORDER.index(args.fail_on)
        if any(SEV_ORDER.index(f["severity"]) <= threshold for f in result["findings"]):
            print(f"[!] findings at/above {args.fail_on} -- exiting 2")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
