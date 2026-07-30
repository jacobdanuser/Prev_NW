#!/usr/bin/env python3
"""Defensive frontend leakage scanner for authorized source trees.

Scans source/build artifacts without contacting dark-web services. It identifies
metadata that could unintentionally leak through frontend code or deployment
artifacts: source maps, environment references, internal URLs, debug endpoints,
credential-like strings, comments, and embedded configuration.

It reports metadata and redacted evidence only; it does not retrieve secrets,
probe targets, exploit endpoints, or access hidden services.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

TEXT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".css", ".map", ".json", ".env", ".yaml", ".yml", ".vue", ".svelte"}
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "dist-cache"}

PATTERNS = {
    "source_map": re.compile(r"(?i)sourceMappingURL=|\.map(?:[\"']|$)"),
    "env_reference": re.compile(r"(?i)(?:process\\.env|import\\.meta\\.env|NEXT_PUBLIC_|VITE_|REACT_APP_)"),
    "internal_host": re.compile(r"(?i)https?://(?:localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|(?:[a-z0-9-]+\\.)*(?:internal|intranet|corp|private)(?:\\.[a-z]{2,})?)"),
    "debug_endpoint": re.compile(r"(?i)(?:/debug|/actuator|/metrics|/healthz|/admin|/internal|/graphql)\\b"),
    "credential_like": re.compile(r"(?i)(?:api[_-]?key|secret|password|passwd|private[_-]?key|authorization|bearer|access[_-]?token)\\s*[:=]"),
    "private_ip": re.compile(r"\\b(?:10\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){2}|192\\.168\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)|172\\.(?:1[6-9]|2\\d|3[0-1])\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d))\\b"),
    "comment": re.compile(r"(?://|/\\*|<!--|#).{0,300}"),
}

@dataclass
class Finding:
    path: str
    category: str
    line: int
    sha256: str
    evidence: str
    severity: str
    recommendation: str


def redact(text: str) -> str:
    # Never persist likely credential values. Keep enough context for remediation.
    text = re.sub(r"(?i)((?:api[_-]?key|secret|password|passwd|private[_-]?key|authorization|bearer|access[_-]?token)\\s*[:=]\\s*)([^,;\\s\\"']+)", r"\\1[REDACTED]", text)
    return text[:500]


def classify(category: str) -> tuple[str, str]:
    table = {
        "credential_like": ("critical", "Remove the value from frontend-delivered artifacts, rotate it if real, and move secrets server-side."),
        "private_ip": ("high", "Remove internal addressing from public bundles or replace it with an intended public endpoint."),
        "internal_host": ("high", "Verify whether the hostname is unintentionally exposed and remove internal infrastructure identifiers."),
        "source_map": ("medium", "Review source-map publication; avoid exposing sensitive source or internal paths in production maps."),
        "env_reference": ("medium", "Verify every exposed environment variable is intentionally public; never embed secrets in frontend variables."),
        "debug_endpoint": ("medium", "Ensure diagnostic/admin endpoints are authenticated and not unnecessarily referenced in public bundles."),
        "comment": ("low", "Review comments for credentials, internal architecture, private URLs, or operational details."),
    }
    return table[category]


def scan_file(path: Path) -> list[Finding]:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for category, pattern in PATTERNS.items():
            if pattern.search(line):
                severity, recommendation = classify(category)
                findings.append(Finding(str(path), category, line_no, digest, redact(line), severity, recommendation))
    return findings


def scan(root: Path) -> dict:
    findings: list[Finding] = []
    files_scanned = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files_scanned += 1
        findings.extend(scan_file(path))
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "authorized frontend source/build tree only",
        "files_scanned": files_scanned,
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
        "dark_web_boundary": "No dark-web/hidden-service crawling, credential acquisition, exploitation, or unauthorized probing is performed. Findings identify leakage that could potentially appear in public frontend artifacts.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, default=Path("frontend_leakage_metadata.json"))
    args = parser.parse_args()
    result = scan(args.root)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Scanned {result['files_scanned']} files; recorded {result['finding_count']} findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
