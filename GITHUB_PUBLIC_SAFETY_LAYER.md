# GitHub public safety and security layer

Updated: 2026-07-29

This document records publicly documented GitHub repository security and safety controls. It does not claim to describe GitHub's private moderation systems, internal abuse-detection models, connector safety checks, or unpublished enforcement logic.

## Publicly documented controls

### 1. Secret scanning

GitHub Secret Scanning detects credentials and other supported secret patterns in repositories. GitHub documents secret scanning as automatically available for public repositories.

Source: https://docs.github.com/en/code-security/concepts/secret-security/about-alerts

### 2. Push protection

Push protection scans pushes for supported secrets and can block a push when a secret is detected. GitHub states that push protection is available for public repositories and that new public repositories owned by personal accounts have secret scanning and push protection enabled by default.

Sources:
- https://docs.github.com/en/code-security/getting-started/github-security-features
- https://github.blog/changelog/2024-03-11-secret-scanning-and-push-protection-are-enabled-by-default-on-new-public-repositories/

### 3. Code scanning / CodeQL

GitHub Code Security includes code scanning for vulnerabilities and coding errors. CodeQL can analyze supported languages and produce code-scanning results.

Source: https://docs.github.com/en/code-security/getting-started/github-security-features

### 4. Dependency and supply-chain security

GitHub documents dependency graph, Dependabot alerts, dependency review, malware alerts, dependency updates, provenance/integrity controls, and SBOM-related capabilities as parts of its security tooling.

Source: https://docs.github.com/en/code-security/getting-started/github-security-features

### 5. Repository visibility and access controls

GitHub supports public, private, and (where applicable) internal repository visibility. Visibility changes affect forks, logs, actions history, security capabilities, and who can access the code.

Source: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility

### 6. Fork/network controls

GitHub repositories have distinct permissions and settings from forks, while public forks remain public. GitHub also documents repository and organization controls governing private-repository forking.

Sources:
- https://docs.github.com/en/pull-requests/reference/forks
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-the-forking-policy-for-your-repository

### 7. Repository feature controls

Repository administrators can configure features such as Issues, Pull Requests, Projects, Actions, Discussions, and security-analysis features.

Source: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository

### 8. Repository archival

An archived repository becomes read-only. GitHub documents that code, commits, branches, releases, issues, pull requests, comments, and security alerts become read-only while archived.

Source: https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories

## Observed public properties of `jacobdanuser/Prev_NW`

The repository was inspected through the connected GitHub repository interface on 2026-07-29.

- Owner: `jacobdanuser`
- Repository: `Prev_NW`
- Visibility: public
- Default branch: `main`
- Archived: no
- Repository ID: `1160473427`
- The repository currently contains a mixture of source-like files, research notes, and project artifacts. Examples observed during the inventory include `README.md`, `name_verifier.py`, `metadata.py`, `report.py`, `nyse_sources.md`, `nyse_public_source_inventory.py`, `examples.py`, `integration_patterns.py`, and other files.

The properties above describe the repository state visible through the GitHub interface at the time of inspection. They do not establish that every listed file is safe to execute.

## Important distinction: public GitHub controls vs. connector safety

GitHub's public documentation describes GitHub's repository security features. It does not document every safety decision made by third-party clients, AI assistants, GitHub Apps, or API connectors before a write operation is submitted.

Therefore, a rejected repository write should not automatically be interpreted as a GitHub platform security alert, GitHub moderation action, or evidence that GitHub classified the repository as malicious. The cause of a rejected operation must be established from the relevant system's documented error information.

## What this document does not claim

- It does not expose GitHub's private security rules or internal detection models.
- It does not reproduce proprietary GitHub source code.
- It does not claim that every security feature is enabled on this specific repository unless GitHub exposes that state publicly.
- It does not treat a blocked write as proof of malicious content.
- It does not attempt to bypass security controls.

## Research principle

Public documentation, observed repository metadata, and inferred behavior are kept separate. This prevents a hypothesis about a safety mechanism from being represented as a confirmed internal implementation detail.
