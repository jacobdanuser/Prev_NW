#!/usr/bin/env python3
"""Defensive public-source terrorism metadata collector for USA/Russia.

Use only with authorized public sources or local documents. The collector
records provenance and high-level references to terrorist organizations,
attacks, designations, investigations, sanctions, and court proceedings.
It does not collect operational instructions, propaganda, credentials, private
personal data, or intelligence from restricted systems.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ORGANIZATIONS = {
    "ISIS/ISIL/Daesh": ["isis", "isil", "daesh", "islamic state"],
    "Al-Qaeda": ["al-qaeda", "al qaeda"],
    "Taliban": ["taliban"],
    "Al-Shabaab": ["al-shabaab", "al shabaab"],
    "Boko Haram": ["boko haram"],
    "Hamas": ["hamas"],
    "Hezbollah": ["hezbollah", "hizballah"],
    "Russian terrorist-designation references": ["terrorist organization", "terrorist designation", "extremist organization"],
}
TOPICS = [
    "attack", "bombing", "kidnapping", "hostage", "financing", "recruitment",
    "propaganda", "designation", "sanctions", "investigation", "indictment",
    "prosecution", "conviction", "court", "law enforcement", "counterterrorism",
    "foreign terrorist organization", "terrorist designation", "extremist designation",
    "military operation", "border security", "cybercrime", "fundraising", "arms trafficking"
]
COUNTRY_TERMS = {
    "USA": ["united states", "u.s.", "usa", "american", "federal bureau of investigation", "department of justice"],
    "Russia": ["russia", "russian", "russian federation", "fsb", "investigative committee"]
}

@dataclass
class Record:
    source: str
    source_type: str
    retrieved_at: str
    sha256: str | None
    title: str | None
    hostname: str | None
    countries_detected: list[str]
    organizations_detected: list[str]
    topics_detected: list[str]
    status: str
    notes: list[str]


def classify(text: str):
    low = text.lower()
    countries = [c for c, terms in COUNTRY_TERMS.items() if any(t in low for t in terms)]
    orgs = [o for o, terms in ORGANIZATIONS.items() if any(t in low for t in terms)]
    topics = [t for t in TOPICS if t.lower() in low]
    return countries, orgs, topics


def inspect_url(url: str, max_bytes: int = 2_000_000) -> Record:
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP(S) sources are supported.")
    req = Request(url, headers={"User-Agent": "Prev_NW-terrorism-public-source-audit/1.0"})
    with urlopen(req, timeout=10) as r:
        data = r.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        text = data.decode("utf-8", errors="replace")
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:300] if m else None
        countries, orgs, topics = classify(text)
        notes = ["Source body is not persisted by this collector."]
        if truncated:
            notes.append("Analysis truncated at max_bytes.")
        return Record(url, "public_url", datetime.now(timezone.utc).isoformat(), hashlib.sha256(data).hexdigest(), title, p.hostname, countries, orgs, topics, str(getattr(r, "status", "unknown")), notes)


def inspect_file(path: Path) -> Record:
    data = path.read_bytes()
    countries, orgs, topics = classify(data.decode("utf-8", errors="replace"))
    return Record(str(path), "local_document", datetime.now(timezone.utc).isoformat(), hashlib.sha256(data).hexdigest(), path.name, None, countries, orgs, topics, "read", ["Explicitly supplied local document."])


def main() -> int:
    ap = argparse.ArgumentParser(description="Authorized USA/Russia terrorism public-source metadata collector")
    ap.add_argument("sources", nargs="+", help="Authorized public URLs or local documents")
    ap.add_argument("--output", default="usa_russia_terrorism_metadata.json")
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
        "scope": "authorized public sources concerning terrorism and designated/extremist organizations in USA/Russia contexts",
        "records": records,
        "factuality_rule": "A name or keyword match is not proof of membership, criminal conduct, terrorist status, or intent. Preserve source context, jurisdiction, legal designation, and evidentiary status separately.",
        "safety_boundary": "No operational terrorist assistance, extremist recruitment/propaganda collection, credential acquisition, private-person targeting, classified access, or unauthorized system access."
    }, indent=2), encoding="utf-8")
    print(f"Wrote {len(records)} records to {args.output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
