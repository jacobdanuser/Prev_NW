# GitHub safety-layer black-box tests

These tests are designed to characterize **observable, public-facing behavior** without bypassing GitHub controls.

## Rules

- Use only a repository and account you are authorized to test.
- Use benign synthetic strings and ordinary source files.
- Do not submit real credentials, tokens, private keys, malware, exploit payloads, or restricted data.
- Do not attempt to evade secret scanning, push protection, authentication, rate limits, or other controls.
- Record only information visible to the authorized tester.

## Test matrix

| ID | Test | Variable | Expected observation |
|---|---|---|---|
| T01 | Read repository metadata | none | Repository properties are returned |
| T02 | Read an ordinary text file | file contents | File is returned |
| T03 | Create an ordinary text file | new file | Normal write succeeds if permissions allow |
| T04 | Update an ordinary text file | existing blob SHA | Normal update succeeds if permissions allow |
| T05 | Search repository files | search terms | Search results identify indexed files where available |
| T06 | Compare refs | base/head refs | Comparison returns differences where available |
| T07 | Create a benign branch | branch name | Branch creation succeeds if permissions allow |
| T08 | Attempt a benign commit | ordinary content | Commit succeeds if repository policy permits |

## Result interpretation

A successful or rejected operation is an **observation**, not proof of the internal implementation that produced it. In particular, a connector-level rejection should not automatically be attributed to GitHub's own security or moderation systems.

## Evidence record

For each test record:

- UTC timestamp
- test ID
- repository and ref
- operation
- input category (never the secret itself)
- result: success / rejected / error
- exact visible error text, if any
- relevant commit SHA, if produced
- relevant public documentation

Never store credentials, access tokens, private keys, or other secrets in the evidence log.
