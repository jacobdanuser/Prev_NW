#!/usr/bin/env python3
"""Authorized public-source metadata collector for USA and Russia.

This tool accepts explicitly supplied public URLs or local documents and
extracts source/provenance metadata plus broad topic/organization mentions.
It does not bypass access controls, access classified material, infiltrate
systems, collect credentials, or target private individuals.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

COUNTRIES = {
    "USA": ["united states", "u.s.", "usa", "america", "american"],
    "Russia": ["russia", "russian", "russian federation"]
}
AREAS = [
    "government", "federal agencies", "state government", "local government",
    "courts", "law", "regulation", "elections", "politics", "economy",
    "finance", "banking", "health", "education", "science", "technology",
    "cybersecurity", "defense", "military", "intelligence", "policing",
    "criminal justice", "terrorism", "counterterrorism", "sanctions",
    "diplomacy", "foreign policy", "trade", "energy", "environment",
    "infrastructure", "transportation", "migration", "humanitarian",
    "media", "communications", "labor", "demographics", "geography"
]

@dataclass
class Record:
    source: str
    source_type: str
    retrieved_at: str
    sha256: str | None
    title: str | None
    hostname: str | None
    countries_detected: list[str]
    areas_detected: list[str]
    status: str
    notes: list[str]


def classify(text: str):
    low = text.lower()
    countries = [c for c, terms in COUNTRIES.items() if any(t in low for t in terms)]
    areas = [a for a in AREAS if a.lower() in low]
    return countries, areas


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
        match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = re.sub(r"\s+", " ", match.group(1)).strip()[:300] if match else None
        countries, areas = classify(text)
        notes = ["Source body is not persisted by this collector."]
        if truncated:
            notes.append("Analysis was truncated at max_bytes.")
        return Record(url, "public_url", datetime.now(timezone.utc).isoformat(), hashlib.sha256(data).hexdigest(), title, p.hostname, countries, areas, str(getattr(r, "status", "unknown")), notes)


def inspect_file(path: Path) -> Record:
    data = path.read_bytes()
    countries, areas = classify(data.decode("utf-8", errors="replace"))
    return Record(str(path), "local_document", datetime.now(timezone.utc).isoformat(), hashlib.sha256(data).hexdigest(), path.name, None, countries, areas, "read", ["Explicitly supplied local document."])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sources", nargs="+", help="Explicitly authorized public URLs or local documents")
    ap.add_argument("--output", default="usa_russia_metadata.json")
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
        "scope": "public and authorized sources concerning USA and Russia",
        "records": records,
        "factuality_rule": "A detected term is not proof of an event, crime, affiliation, or intent; retain source context and legal findings separately.",
        "safety_boundary": "No classified-data access, unauthorized system access, credential collection, or private-person targeting."
    }, indent=2), encoding="utf-8")
    print(f"Wrote {len(records)} records to {args.output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
