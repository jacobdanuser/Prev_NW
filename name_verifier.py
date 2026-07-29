#!/usr/bin/env python3
"""Passive scanner for corporate-name discrepancies in authorized evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DEFAULT_VARIANTS = ("BitDance", "ByteDance")
TEXT_EXTENSIONS = {".txt", ".md", ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".xml", ".html", ".csv", ".log"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_file(path: Path, variants: tuple[str, ...]) -> list[dict]:
    if path.suffix.lower() not in TEXT_EXTENSIONS:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for variant in variants:
            if variant.casefold() in line.casefold():
                findings.append({
                    "file": str(path),
                    "line": line_number,
                    "observed_name": variant,
                    "context": line.strip(),
                    "status": "DISCREPANCY REQUIRING VERIFICATION" if variant.casefold() != "bytedance" else "REFERENCE NAME OBSERVED",
                })
    return findings


def scan(root: Path, variants: tuple[str, ...]) -> dict:
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    findings = []
    metadata = []
    for path in files:
        try:
            stat = path.stat()
            metadata.append({
                "file": str(path),
                "size": stat.st_size,
                "modified_ns": stat.st_mtime_ns,
                "sha256": sha256(path),
            })
            findings.extend(scan_file(path, variants))
        except OSError:
            continue
    return {"variants": list(variants), "metadata": metadata, "findings": findings}


def main() -> None:
    parser = argparse.ArgumentParser(description="Passively scan authorized material for configured name variants.")
    parser.add_argument("path", type=Path)
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    report = scan(args.path, DEFAULT_VARIANTS)
    print("CORPORATE-NAME VERIFICATION ALERT")
    print(f"Files inspected: {len(report['metadata'])}")
    print(f"Findings: {len(report['findings'])}")
    for finding in report["findings"]:
        print(f"- {finding['file']}:{finding['line']} — {finding['observed_name']} — {finding['status']}")
        print(f"  {finding['context']}")
    print("\nNOTE: A naming discrepancy does not establish intentional misrepresentation.")

    if args.json_path:
        args.json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
