# SAID Phase 33 — Independent Release Review and Ruleset Assessment

SAID — Secure Asset Identity & Detection · Powered by Ithute Digital Solutions.

This phase introduces an **offline, review-only** security and operations
signoff package assessment. It does not authenticate human reviewers, query
GitHub rulesets, grant deployment permission, or operate national CEIR
infrastructure.

## Usage

```sh
python -m said.independent_review --review-package /private/reviews/release-review.json
```

The JSON schema identifier is `said.mock.release-review.v1`. It requires
the exact 40-character commit SHA, positive GitHub CI run ID,
64-character hash of the previously verified CI report, a declared
`verified_ci_review_candidate`, original code author and planned deployer
subjects, and exactly two explicit signoffs.

Signoffs must be distinct named roles (`security_reviewer` and
`operations_reviewer`), reference different people who are also separate
from the code author and deployer, declare approval and provide a reference
and timezone-aware timestamp no older than seven days. Missing, denied or
pending approvals fail closed.

The `ruleset_assessment` portion is a *locally supplied* inventory with
schema `said.mock.rulesets.v1`, `complete: true`, and at least one
active branch ruleset declared applicable to main. The assessor rejects
unreviewed bypass actors and requires declared pull-request, status-check,
non-fast-forward and deletion-prevention rule types.

**These checks evaluate only the operator-supplied JSON representation,
not GitHub's actual ruleset activation, true effective bypass permissions,
or authentically signed human approval.** GitHub's ruleset data and external
approval still need independent collection and authentication. The input
hash also is not checked against an externally retrieved previous report.

A successful result is `review_candidate=true` only.
`staging_deploy_authorized`, `production_deploy_authorized` and
`telecom_operations_enabled` always remain false. No external network
or subscriber action is enabled.

## Follow-on prerequisites

Future phases should obtain GitHub rulesets and PR-review records via
fixed-origin authenticated read-only GitHub APIs, bind them to the exact
approved commit and reviewer identities, and independently inspect
effective organization/enterprise bypass settings. This must remain
separate from formal government, operator and infrastructure authorization.
