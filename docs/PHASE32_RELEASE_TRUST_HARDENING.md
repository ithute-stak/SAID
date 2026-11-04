# SAID Phase 32 — GitHub Release Evidence Trust Hardening

Phase 31's already-merged GitHub verification is tightened to reject API redirects, confirm the exact workflow path, bind pull-request runs to the expected `main` base and commit head SHA, reject unexpected push branches, and reject duplicated job-step names. Main-branch protection checks also reject enabled force pushes or branch deletion.

The GitHub token remains in `SAID_GITHUB_READ_TOKEN`; neither token nor private keys are logged. The verifier makes read-only HTTPS requests to the hardcoded SAID GitHub API endpoints only. Unit tests mock network responses and test malicious or inconsistent metadata.

The result continues to be **review only**. Passing checks neither authorize staging nor production, certify national CEIR activities, authenticate independent backups, nor enable telecom network action. GitHub API data is not a signed attestation. Ruleset/bypass and human external authorization still require independent review.
