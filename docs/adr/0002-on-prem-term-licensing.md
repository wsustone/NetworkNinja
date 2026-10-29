# 0002: On-prem term licensing, not SaaS first

Date: 2026-10-28 · Status: Accepted

## Context

Most target exercises run on air-gapped or classified networks. Hosted services for DoD need FedRAMP and impact-level authorization before a first sale. Buyers already purchase installed software.

## Decision

Sell an on-prem term license (annual, per site or exercise network), with perpetual-plus-maintenance and OEM/integrator options. Tiers: Base, Pro, Enterprise, plus custom message sets as a separately licensed add-on. SaaS comes later, for unclassified and commercial training only.

## Consequences

- Licensing must work fully offline: a signed license file checked locally, never phoning home.
- Expiry warns and then runs during a grace period; monitoring is never cut off mid-exercise.
- Updates ship as signed offline bundles.
- Licensing is built in milestone 7, before the first paid trial.
