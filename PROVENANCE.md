# Provenance

Where this code came from, written down so it can't get lost.

## Origin

KAG was developed by **Mike Storm** in a private repository, as an
independent project that grew out of his KIL work. First-built credit is his
and is permanent. KIL's own provenance is recorded in its own repository.

## Import record

Filled in by the first PR that brings the code across.

| | |
|---|---|
| Imported from | private repository, commit `_______` |
| Import date | `____-__-__` |
| Imported by | |
| KTP release pinned at import | `v_.._._` |
| KIL release depended on, if any | `v_.._._` |

Later imports from the same origin append a row; nothing above is rewritten.

### Source-only core import — 2026-10-02

| Field | Record |
|---|---|
| Imported from | Mike Storm's `gatekeeper454/KTP-Component-Dev`, commit `a79bc5023c02345fbd6bb9a64286c9a463e5cf7e` |
| Prepared source snapshot | `11d18c8dcb436ce70cfe671bf6919bbae7fd8be7`; files copied without its private commit ancestry |
| Imported by | Mike Storm; acceptance pending public import review |
| Scope | 59 original blobs: seven core packages, their tests and modeled fixtures, and `go.mod`; exact paths and blob identities in `SOURCE-IMPORT.json` |
| KTP comparison baseline | `v2.1.0`; experimental contracts do not establish adopted-profile conformance |
| Draft execution/evidence reference | KTP PR #139 at `e4bcc3f9e337309fdd521939998a7c941ffda245` |
| KIL runtime dependency | None; no qualified KIL release claimed |

Original module and import paths are preserved for byte-exact provenance,
not as a network dependency on the private repository. The module has no
third-party dependencies; no `go.sum` is needed for this import. The
conformance runner is reserved for a separate contribution.

Core tests and modeled fixtures do not establish real supplier identity,
durable storage, target effects, independent validation or conformance.
Original source security evidence is stale for this public import and is
not security clearance. Source-bound reviewer evidence, contextual rule
coverage and accountable dispositions remain release requirements; leaving
environment-specific release pipelines behind does not waive them.

Mike Storm retains first-built authorship. Material AI assistance disclosure:
OpenAI Codex; exact deployed model/version not independently established.
Assistance was used to prepare this import, document its limits and verify its
scope and gates; the contributor and DCO signer is Mike Storm.
KTP specification attribution remains NMCITRA's; see the
[canonical KTP citation](https://github.com/nmcitra/ktp-rfc/blob/main/CITATION.cff).

Disclosure correction, 2026-10-02: the GPT-6 label in source import commit
`e13d5855adc9834ab62fc167ba348ffd18aca170` was unverified and is superseded
by the disclosure above. The historical commit is preserved unchanged.
This correction changes contribution metadata only.

## What stayed behind

Product-specific adapters, deployment guides, evidence bundles and release
pipeline configuration for named environments remain in the working
repository. This repository carries the core and its declared interfaces.

## Authorship convention

People are authors. Commits carry a DCO sign-off naming the person who wrote
or is entitled to contribute the change. A tool is never an author.

This project will be registered in the Open Trust Commons and follows its
disclosure rule: where AI assistance was material to a contribution, the
contribution says so, in the commit body or the PR, naming the model and
version where practical. Disclosure is per contribution; authorship is the
person's.

## Separate draft runner contribution — 2026-10-02

Mike Storm directed and is accountable for this contribution. Material
OpenAI Codex assistance (GPT-6) was used to integrate the prepared runner,
document its limits and verify scope, host gates and the local report.
The contributor and DCO signer is Mike Storm.

Eight new files are copied exactly from prepared candidate
`8411f358283071df75fc1dd12ce59dd4072dcee6`: fixture loader and preflight,
package-local adapter, report and runner tests, fixture and its upstream
NOTICE, and `scripts/run-conformance.sh`. No private preparation ancestry is
imported. All 59 original source blobs and `SOURCE-IMPORT.json` stay unchanged.
README and this provenance record are additive; host status, root NOTICE,
governance, CI and host check scripts are preserved. This draft contribution
is stacked on the source import until that PR merges.

The fixture comes from canonical KTP commit
`7855966e8c061dae165d4d66ee2527bacbb59d6c`, path
`specifications/conformance/consequential-action-execution-v1.json`, with
SHA-256 `732e293673461807d9ae491ac3d00b1c42dbb4143c5b3bf6056ab3d44993f25d`.
The execution/evidence specification SHA-256 is
`51f11db0305585efba81cd99054bd6bd0ae1b87d84cc0a7c8a844879a7e64c5d`.
The fixture is distributed under Apache-2.0; exact upstream
[NOTICE](internal/execution/testdata/NOTICE) is retained alongside it,
SHA-256 `92294ef1c8e9f6a137f3036f6d8d61aa28d363ef4ed89ac311b3fb1d6611974c`.
KTP specification attribution remains NMCITRA's and Chris Perkins's;
[canonical citation](https://github.com/nmcitra/ktp-rfc/blob/main/CITATION.cff).

The request-only adapter receives no vector IDs, labels or expected answers.
Observed values come from imported reducer operations and modeled ledger,
recorder and target state; the initial-send oracle remains test-only. Reports
retain detached result snapshots and fixed error categories rather than
arbitrary panic payloads. Required validated-permit, production time,
persistence, live authority, authenticated non-dispatch coverage, renewed
decision correlation and continuing safe-transition gaps remain blockers.
Eleven schema vectors and the mutation-validation vector are not executed.
Expected local results are 20 cases, 40 attempts, 12 modeled matches and
8 unsupported cases, with qualification false and CLI exit 1. No production
conformance, independent validation, source security clearance, signing
approval, tag or release is asserted.
