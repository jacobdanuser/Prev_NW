#!/usr/bin/env python3
"""Authorized public-source metadata scanner.

This utility does NOT crawl hidden services, bypass access controls, authenticate
against illicit services, deanonymize users, or collect credentials. It analyzes
URLs/files explicitly supplied by the operator and records metadata only.

Use only against sources you are authorized to examine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ONION_RE = re.compile(r"^(?:[a-z2-7]{56})\\.onion$", re.I)
SENSITIVE_KEYS = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization|cookie)")


@dataclass
class SourceMetadata:
    source: str
    source_type: str
    hostname: str | None
    is_onion_hostname: bool
    retrieved_at: str
    status: str
    content_type: str | None
    content_length: int | None
    sha256: str | None
    title: str | None
    notes: list[str]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def redact_key_names(mapping: dict) -> dict:
    """Return metadata keys only; never copy sensitive values."""
    return {k: "[REDACTED_KEY]" if SENSITIVE_KEYS.search(k) else type(v).__name__ for k, v in mapping.items()}


def inspect_url(url: str, timeout: float = 10.0, max_bytes: int = 2_000_000) -> SourceMetadata:
    parsed = urlparse(url)
    host = parsed.hostname
    is_onion = bool(host and ONION_RE.fullmatch(host))

    # Deliberately refuse direct .onion retrieval. Operators may catalog an onion
    # address they already possess, but this scanner does not connect to it.
    if is_onion:
        return SourceMetadata(
            source=url,
            source_type="URL",
            hostname=host,
            is_onion_hostname=True,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            status="catalogued_not_fetched",
            content_type=None,
            content_length=None,
            sha256=None,
            title=None,
            notes=["Direct hidden-service retrieval is disabled; analyze only authorized public mirrors, exports, or operator-supplied files."],
        )

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP(S) URLs are accepted for remote metadata collection.")

    req = Request(url, headers={"User-Agent": "Prev_NW-authorized-metadata-audit/1.0"})
    with urlopen(req, timeout=timeout) as response:
        data = response.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        content_type = response.headers.get_content_type()
        title = None
        if content_type == "text/html":
            text = data.decode("utf-8", errors="replace")
            match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            if match:
                title = re.sub(r"\\s+", " ", match.group(1)).strip()[:300]
        notes = ["Response body was not stored by this script."]
        if truncated:
            notes.append("Hash covers only the first configured byte limit; content was truncated.")
        return SourceMetadata(
            source=url,
            source_type="URL",
            hostname=host,
            is_onion_hostname=False,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            status=str(getattr(response, "status", "unknown")),
            content_type=content_type,
            content_length=response.headers.get("Content-Length"),
            sha256=sha256_bytes(data),
            title=title,
            notes=notes,
        )


def inspect_file(path: Path) -> SourceMetadata:
    data = path.read_bytes()
    mime, _ = mimetypes.guess_type(path.name)
    return SourceMetadata(
        source=str(path),
        source_type="local_file",
        hostname=None,
        is_onion_hostname=False,
        retrieved_at=datetime.now(timezone.utc).isoformat(),
        status="read",
        content_type=mime,
        content_length=len(data),
        sha256=sha256_bytes(data),
        title=None,
        notes=["Local file was explicitly supplied to the scanner."],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorized metadata-only source auditor")
    parser.add_argument("sources", nargs="+", help="Explicitly supplied URLs or local files")
    parser.add_argument("--output", default="dark_web_metadata.json")
    args = parser.parse_args()

    results = []
    for source in args.sources:
        try:
            if source.startswith(("http://", "https://")):
                result = inspect_url(source)
            else:
                result = inspect_file(Path(source))
            results.append(asdict(result))
        except Exception as exc:
            results.append({
                "source": source,
                "status": "error",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            })

    Path(args.output).write_text(json.dumps({
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "authorized public-source metadata only",
        "results": results,
    }, indent=2), encoding="utf-8")
    print(f"Wrote {len(results)} metadata records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
