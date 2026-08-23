# Architecture decision records

An architecture decision record (ADR) captures one decision that is
security-sensitive, expensive to reverse, or otherwise hard to infer from the
code. Routine choices do not need an ADR; write one when a future maintainer
would otherwise have to reconstruct the reasoning from scratch.

## File naming

One decision per file, named `NNNN-slug.md`:

- `NNNN` is a zero-padded four-digit sequence number, assigned in order and
  never reused.
- `slug` is a short lowercase-hyphenated summary of the decision.

Copy [`template.md`](template.md) to start a new record. Numbers are claimed
when the file is committed; if two branches claim the same number, the later
one is renumbered before merge.

## Status lifecycle

Every ADR carries exactly one status.

| Status | Meaning |
| --- | --- |
| Proposed | Written and under review. Not yet binding. |
| Accepted | Reviewed and binding. Code is expected to follow it. |
| Rejected | Reviewed and declined. Kept so the option is not reconsidered blindly. |
| Deprecated | No longer applies, and nothing replaced it. |
| Superseded | Replaced by a later ADR. |

An ADR is immutable once Accepted, apart from status changes and link
corrections. Changing a decision means writing a new ADR, not editing the old
one, so the history of what was believed and when stays readable.

To supersede an earlier decision:

1. Write the new ADR with status Accepted. Its Context explains what changed;
   its References link the ADR it replaces.
2. Change the earlier ADR's status line to
   `Superseded by [ADR-NNNN](NNNN-slug.md)` and leave the rest of its text
   alone.
3. Update the index below.

A decision that is abandoned without a replacement becomes Deprecated instead,
with a one-line note saying why.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-native-reconciliation.md) | Native declarative reconciliation | Accepted |

## Review

This repository currently has a single maintainer committing directly to
`main`. Acceptance review for an ADR is performed by automated code review of
the commit that introduces it, in place of a second human reviewer. If the
project gains additional maintainers, ADRs should be accepted through ordinary
pull-request review.
