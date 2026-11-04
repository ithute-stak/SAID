# SAID Phase 31 — Authenticated GitHub CI evidence

The read-only CLI `python -m said.github_evidence --commit-sha <40-hex-SHA> --run-id <number>` retrieves a GitHub Actions run and its jobs from fixed repository `ithute-stak/SAID` using `SAID_GITHUB_READ_TOKEN` in the environment. Never pass tokens on the command line or commit them.

The verifier requires an exact SHA and run ID, matching repository and expected workflow path, pull-request event, completed successful run, exactly one successful job, and every critical CI step marked completed and successful. It rejects partial, failed, skipped, mismatched, truncated job lists and inaccessible GitHub responses. A token with Actions read permission to the repository is needed; the test suite substitutes a mock fetch function without network access.

This is **authenticated API evidence, not a cryptographic attestation**. GitHub API data is trusted subject to TLS, GitHub authorization and token security. This phase does NOT prove branch protection, signed commits, code review, infrastructure security, independent audit evidence, HSM custody, telecom permissions, or release authorization. `staging_deploy_authorized` and `production_deploy_authorized` always remain false. The CLI does not deploy any services or talk to any telecom operator.
