#!/usr/bin/env python3
"""Record and inspect public NYSE source references without contacting exchange systems."""

from __future__ import annotations

import json
from pathlib import Path

SOURCES = {
    "developer_portal": "https://developer.nyse.com/",
    "market_data_documents": "https://www.nyse.com/market-data/documents",
    "technical_documents": "https://www.nyse.com/market-data/technical-documents",
    "data_products": "https://www.nyse.com/data-products/",
    "reference_data": "https://www.nyse.com/market-data/reference",
    "corporate_actions": "https://www.nyse.com/market-data/corporate-actions",
    "connectivity_documents": "https://www.nyse.com/connectivity/documents",
    "nyse_cloud": "https://www.nyse.com/nyse-cloud",
}


def build_inventory(output: str | Path = "nyse_sources.json") -> dict:
    inventory = {
        "purpose": "Public-source inventory for defensive research and local integration development",
        "external_system_access": False,
        "sources": SOURCES,
    }
    Path(output).write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    return inventory


if __name__ == "__main__":
    result = build_inventory()
    print(f"Recorded {len(result['sources'])} public NYSE source references.")
