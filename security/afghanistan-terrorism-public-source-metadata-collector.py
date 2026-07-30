#!/usr/bin/env python3
"""Authorized public-source OSINT metadata collector.

Purpose: normalize public, lawful reporting about Afghanistan and designated
terrorist organizations (including Taliban and ISIS/ISIL/Daesh) without
contacting, infiltrating, or collecting operational material from extremist
infrastructure.

The collector accepts operator-supplied URLs or local documents and records
source/provenance metadata. It does not scrape extremist propaganda, solicit
contacts, obtain credentials, facilitate operations, or identify private people.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ORG_TERMS = {
    "Taliban": ["taliban"],
    "ISIS/ISIL/Daesh": ["isis", "isil", "daesh", "islamic state"],
    "Al-Qaeda": ["al-qaeda", "al qaeda"],
}
AREAS = [
    "governance", "security", "terrorism", "counterterrorism", "conflict",
    "humanitarian", "migration", "displacement", "economy", "public_health",
    "education", "infrastructure", "law", "sanctions", "diplomacy",
    "military", "politics", "geography", "trade", "communications"
]

@dataclass
class Record:
    source: str
    source_type: str
    retrieved_at: str
    sha256: str | None
    title: str | None
    hostname: str | None
    organizations_detected: list[str]
    areas_detected: list[str]
    status: str
    notes: list[str]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def classify(text: str) -> tuple[list[str], list[str]]:
    low = text.lower()
    orgs = [name for name, terms in ORG_TERMS.items() if any(t in low for t in terms)]
    areas = [a for a in AREAS if a.replace("_", " ") in low or a in low]
    return orgs, areas


def inspect_url(url: str, max_bytes: int = 2_000_000) -> Record:
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP(S) sources are supported.")
    req = Request(url, headers={"User-Agent": "Prev_NW-public-source-audit/1.0"})
    with urlopen(req, timeout=10) as r:
        data = r.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        text = data.decode("utf-8", errors="replace")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:300] if title_match else None
        orgs, areas = classify(text)
        notes = ["Source body is not persisted by this collector."]
        if truncated:
            notes.append("Analysis was truncated at max_bytes.")
        return Record(url, "public_url", datetime.now(timezone.utc).isoformat(), digest(data), title, p.hostname, orgs, areas, str(getattr(r, "status", "unknown")), notes)


def inspect_file(path: Path) -> Record:
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    orgs, areas = classify(text)
    return Record(str(path), "local_document", datetime.now(timezone.utc).isoformat(), digest(data), path.name, None, orgs, areas, "read", ["Explicitly supplied local document."])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sources", nargs="+", help="Explicitly authorized URLs or local documents")
    ap.add_argument("--output", default="afghanistan_terrorism_metadata.json")
    args = ap.parse_args()
    records = []
    for source in args.sources:
        try:
            records.append(asdict(inspect_url(source) if source.startswith(("http://", "https://")) else inspect_file(Path(source))))
        except Exception as exc:
            records.append({"source": source, "status": "error", "error_type": type(exc).__name__, "error": str(exc)})
    Path(args.output).write_text(json.dumps({
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "public and authorized sources concerning Afghanistan and terrorism",
        "records": records,
        "factuality_rule": "Organization mentions are not evidence of criminal conduct or organizational responsibility; preserve source context and legal findings separately.",
        "safety_boundary": "No extremist-site infiltration, credential collection, operational assistance, propaganda amplification, or unauthorized access."
    }, indent=2), encoding="utf-8")
    print(f"Wrote {len(records)} records to {args.output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
