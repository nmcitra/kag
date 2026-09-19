# Governance

How this repository is run, who does what, and when the arrangement is reviewed.

## Roles

| Role | Who | What it means |
|---|---|---|
| **Maintainer and owner of record** | Mike Storm | Built KAG first. Reviews and merges contributions, cuts releases, speaks for the project in the Open Trust Commons. The only owner. |
| **Host** | Chris Perkins | Controls the GitHub account the repository lives under, keeps the protection rules and CI running, approves first-time contributors' CI runs. A fact about where the code lives, not an ownership claim. |

## How the maintainer changes

By the maintainer's own commit naming a successor, or, if the maintainer is unreachable, by the inactivity rule below. The host does not appoint maintainers.

## Inactivity

If no maintainer commit, review or release lands for **180 days**, the project's Commons state becomes `UNMAINTAINED` on that day, by the calendar and not by anyone's hand. The repository stays public and forkable. A returning maintainer clears it with one commit.

## Independence, stated plainly

The host is the author of the specification this project implements. That disqualifies the host from supplying independent validation of it. So does maintaining it. "Independent" here means what the Open Trust Commons means: a party who fails none of `EVIDENCE-MODEL.md`'s tests (no shared founders or funders, no advisory or reciprocal-review relationship, no employment, no contributed code, no commercial dependency, no substantial prior collaboration) running the published conformance vectors against a tagged release. Until such a run exists, `independent_validation` in `otcs.yaml` is 0, and the number is the honest one.

## Review of this arrangement

Reviewed on **2026-12-10**. On that day the host and maintainer confirm, in this file, that hosting still serves the project, or reopen the question. Nothing here is permanent by default; a review date that passes without a line added here is itself a finding.

## Changing this file

By PR, one review, like everything else. The maintainer's approval is required for changes to Roles; the host's for changes to Inactivity.
