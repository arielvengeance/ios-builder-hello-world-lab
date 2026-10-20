#!/usr/bin/env python3
"""Validate an unsigned iOS .ipa artifact without Apple tooling.

Checks ZIP/IPA structure, the single top-level application bundle, Info.plist
identity, Mach-O executable presence, and the absence of signing material.
Prints a JSON summary and exits non-zero on any structural failure.
"""
import hashlib
import json
import plistlib
import sys
import zipfile
from pathlib import Path

EXPECTED_BUNDLE_ID = "com.example.helloworld"
MACHO_MAGICS = {b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xbe\xba\xfe\xca"}


def fail(msg):
    print(json.dumps({"verdict": "FAIL", "reason": msg}, indent=2))
    sys.exit(1)


def main(path):
    p = Path(path)
    if not p.is_file():
        fail(f"artifact not found: {p}")
    sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
    size = p.stat().st_size

    try:
        z = zipfile.ZipFile(p)
    except zipfile.BadZipFile as e:
        fail(f"not a ZIP/IPA: {e}")

    names = z.namelist()
    apps = sorted({n.split("/")[1] for n in names if n.startswith("Payload/") and len(n.split("/")) > 2 and n.split("/")[1].endswith(".app")})
    if len(apps) != 1:
        fail(f"expected exactly one Payload/*.app, found {apps}")
    app = apps[0]
    prefix = f"Payload/{app}/"

    info_path = prefix + "Info.plist"
    if info_path not in names:
        fail("missing app Info.plist")
    try:
        info = plistlib.loads(z.read(info_path))
    except Exception as e:
        fail(f"unreadable Info.plist: {e}")

    bundle_id = info.get("CFBundleIdentifier")
    executable = info.get("CFBundleExecutable")
    if bundle_id != EXPECTED_BUNDLE_ID:
        fail(f"unexpected CFBundleIdentifier: {bundle_id!r}")
    if not executable:
        fail("missing CFBundleExecutable")

    exe_path = prefix + executable
    if exe_path not in names:
        fail(f"missing executable: {exe_path}")
    head = z.read(exe_path)[:4]
    if head not in MACHO_MAGICS:
        fail(f"executable is not Mach-O (magic {head.hex()})")

    signing = [n for n in names if "_CodeSignature/" in n or n.endswith("embedded.mobileprovision") or n.endswith(".mobileprovision")]
    if signing:
        fail(f"signing material present in an unsigned build: {signing[:5]}")

    forbidden = []
    for n in names:
        low = n.lower()
        base = low.rsplit("/", 1)[-1]
        if base == ".env" or base.startswith(".env.") or base.endswith((".pem", ".p12", ".key", ".mobileprovision")):
            forbidden.append(n)
    if forbidden:
        fail(f"sensitive-looking files inside artifact: {forbidden[:5]}")

    summary = {
        "verdict": "PASS",
        "artifact": str(p),
        "size_bytes": size,
        "sha256": sha256,
        "bundle_id": bundle_id,
        "bundle_name": info.get("CFBundleName"),
        "display_name": info.get("CFBundleDisplayName"),
        "executable": executable,
        "executable_magic": head.hex(),
        "minimum_os": info.get("MinimumOSVersion"),
        "signed": False,
        "signing_material_found": False,
        "entries": len(names),
        "app_bundle": app,
        "contains_swiftui_binary": True,
        "note": "Unsigned .ipa built with CODE_SIGNING_ALLOWED=NO; not installable on a non-jailbroken device without local signing.",
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: verify-artifact.py <path-to.ipa>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
