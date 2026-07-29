#!/usr/bin/env python3
"""Generate a local test record without probing or bypassing GitHub controls."""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

TESTS = [
    {"id": "T01", "operation": "repository metadata read", "risk": "benign"},
    {"id": "T02", "operation": "ordinary file read", "risk": "benign"},
    {"id": "T03", "operation": "ordinary file create", "risk": "benign"},
    {"id": "T04", "operation": "ordinary file update", "risk": "benign"},
    {"id": "T05", "operation": "repository file search", "risk": "benign"},
    {"id": "T06", "operation": "ref comparison", "risk": "benign"},
]


def make_record() -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "repository": "jacobdanuser/Prev_NW",
        "mode": "documentation-only; no external probing",
        "tests": [{**test, "status": "not-run"} for test in TESTS],
        "interpretation": "This runner records a controlled test plan. It does not attempt to bypass or defeat GitHub security controls.",
    }


if __name__ == "__main__":
    output = Path("safety-layer-tests/test-record.json")
    output.write_text(json.dumps(make_record(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output}")
