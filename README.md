# Prev_NW — Corporate Name Verification Audit

A defensive, evidence-oriented toolkit for identifying and documenting naming discrepancies in supplied source code, metadata, documents, and other locally authorized material.

## Scope

The initial use case is to compare occurrences of names such as `BitDance` and `ByteDance` and flag them for verification. A detected discrepancy is **not** treated as proof of deception, fraud, or wrongdoing.

The project is designed to:

- extract file metadata;
- search supplied text for configured name variants;
- preserve evidence locations and context;
- classify findings as observations requiring verification;
- generate a neutral audit report;
- avoid attacking, modifying, probing, or accessing external systems.

## Example finding

```text
CORPORATE-NAME VERIFICATION ALERT

Observed name: BitDance
Expected/verified name: ByteDance
Status: DISCREPANCY REQUIRING VERIFICATION

Evidence:
- Source/document: example.txt
- Location: line 42
- Match: BitDance

This alert does not establish intentional misrepresentation.
Verify the legal name, trade name, and jurisdiction-specific registration
before drawing conclusions.
```

## Usage

Run the analyzer against material you are authorized to inspect:

```bash
python name_verifier.py ./evidence
```

The analyzer is intentionally local and passive. It does not contact ByteDance, TikTok, GitHub, or any other external target.

## Evidence standards

A useful finding should distinguish between:

1. **Observed text** — what the supplied material actually contains.
2. **Metadata** — file name, size, timestamps, and hashes where available.
3. **Reference name** — the name being used for comparison.
4. **Verification status** — whether an authoritative source has independently established the relevant legal/trade name.
5. **Conclusion** — kept separate from the observation so that the tool does not infer intent.

## License

Use and adapt this repository for authorized defensive auditing and documentation.