#!/usr/bin/env python3
"""Render JSON findings as a neutral verification report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    data = json.loads(args.report.read_text(encoding="utf-8"))

    print("CORPORATE-NAME VERIFICATION REPORT")
    print("===================================")
    print("Observed naming differences are findings for verification, not conclusions about intent.\n")
    for item in data.get("findings", []):
        print(f"File: {item['file']}")
        print(f"Line: {item['line']}")
        print(f"Observed name: {item['observed_name']}")
        print(f"Status: {item['status']}")
        print(f"Context: {item['context']}\n")


if __name__ == "__main__":
    main()
