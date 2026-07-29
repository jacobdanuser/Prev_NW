# NYSE source inventory

This file records authoritative NYSE sources used to design the local integration code in this repository. It does **not** copy proprietary NYSE feed implementations or attempt to access restricted exchange infrastructure.

## Official sources

- NYSE Developer Portal: https://developer.nyse.com/
- NYSE Market Data Documents: https://www.nyse.com/market-data/documents
- NYSE Proprietary Data Technical Documents: https://www.nyse.com/market-data/technical-documents
- NYSE Data Products: https://www.nyse.com/data-products/
- NYSE Reference Data: https://www.nyse.com/market-data/reference
- NYSE Corporate Actions: https://www.nyse.com/market-data/corporate-actions
- NYSE Connectivity Documents: https://www.nyse.com/connectivity/documents
- NYSE Market Data via AWS: https://www.nyse.com/nyse-cloud

## What can be sourced

NYSE publishes technical specifications for feeds including Integrated, OpenBook, BBO, Trades, Order Imbalances, Pillar Depth, Security Master, Corporate Actions, and historical TAQ products. Access to some feeds and redistribution is governed by contracts, policies, credentials, and fees.

The repository therefore stores **our own client-side analysis and collection code**, plus source references and metadata, rather than copying NYSE proprietary code or restricted market-data payloads.

## Safety boundary

`nyse_public_source_inventory.py` is a passive source/document inventory tool. It does not connect to trading systems, submit orders, bypass authentication, probe exchange infrastructure, or attempt to obtain restricted feeds.
