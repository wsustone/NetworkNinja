# 0004: Receive-only by default

Date: 2026-10-28 · Status: Accepted

## Context

Security reviewers on exercise networks need a simple, defensible story. A tool that never transmits onto the exercise network is far easier to approve.

## Decision

The capture interface is receive-only. The dashboard runs on a separate management interface. The only feature that transmits, network replay, is a separately enabled Pro feature bound to its own interface, off by default.

## Consequences

- Most accreditation questions for the MVP reduce to "it listens; it never sends."
- Network replay must be clearly documented as the exception for security reviews.
- Replay into the dashboard is always safe and is part of the Base tier.
