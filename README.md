# KAG — Kinetic Action Gateway

An implementation of the [Kinetic Trust Protocol](https://github.com/nmcitra/ktp-rfc) at the point where an authorized decision becomes a real action: the gateway binds one signed decision to one exact operation, holds it to the decision at release, and records what happened.

**Maintainer:** Mike Storm. **Host:** the KTP project. KAG was built first by Mike; see `NOTICE` and `PROVENANCE.md`.

**Status: EXPERIMENTAL · review by 2026-12-10.** Nothing here is a conformance claim until a tagged release runs the published vectors and says so. See `GOVERNANCE.md`.

## What this repository is

- The core, in Go: closed ingress, the fixed-action library, transport identity, actor and decision enforcement, the execution reducer, and the evidence recorder.
- The conformance runner for the KTP consequential-action specification, once that specification is adopted.
- Vendor-neutral. KAG consumes a signed decision and an observation feed through declared interfaces; anything that wires a specific product's feed, identity service, or target lives elsewhere.

## What this repository is not

- The specification. That is [`ktp-rfc`](https://github.com/nmcitra/ktp-rfc); KAG pins a release of it by tag.
- A deployment guide. Those name products; this repo does not.
- KIL. KIL verifies signed state and decides per action; KAG holds the action to that decision. They are separate implementations with separate repositories, and KAG depends on KIL's published interface, never on its internals.

## Building against KTP

State the KTP release you built against, by tag. Between KTP releases, `main` there may carry material no tag contains yet; if you build against that, pin the exact commit and say so.

## Source-only core import (2026-10-02)

This import contains seven core packages, their tests and modeled fixtures,
and `go.mod`: 59 original blobs recorded in [`SOURCE-IMPORT.json`](SOURCE-IMPORT.json).
The original module and import paths are retained for exact provenance. The
module has no third-party dependencies and no KIL runtime dependency.

The KTP comparison baseline is `v2.1.0`; the draft execution/evidence reference
is KTP PR #139 at `e4bcc3f9e337309fdd521939998a7c941ffda245`.
These are reference points, not adopted-profile conformance claims. The
conformance runner is deferred to a separate PR; this import contains only
the core libraries and their existing tests and fixtures.

Run `bash scripts/check-all.sh` with Go 1.27.1 or later. Passing core tests
provides modeled evidence only. Prior source security evidence is stale for
this public import and does not clear it for release; fresh source-bound
security review and published conformance receipts remain release gates.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Short version: one PR per change, DCO sign-off on every commit, green checks, no product names, no generated readers or transcripts.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

## Local draft conformance reports

The separate runner contribution is stacked on the source-only import until
that import merges. It adds package-local tests and a local CLI; the
EXPERIMENTAL status and release gates above still apply.

The adapter exercises the imported reducer and modeled ledger, recorder and
target against 20 pinned draft requests, with two independent attempts per
case. Its initial-send oracle is test-only. Twelve modeled matches and eight
unsupported cases are expected; qualification remains false and the explicit
qualification command exits 1. Normal host checks test the harness and skip
the explicit qualification run.

Run offline with an existing local fixture and a new absolute report path
outside source repositories; the report parent directory must already exist:

```sh
bash scripts/run-conformance.sh \
  --fixture /absolute/local/consequential-action-execution-v1.json \
  --fixture-sha256 732e293673461807d9ae491ac3d00b1c42dbb4143c5b3bf6056ab3d44993f25d \
  --report /absolute/report-directory/new-report.json \
  --profile-root /absolute/local/ktp-checkout
```

Profile verification requires clean KTP HEAD
`7855966e8c061dae165d4d66ee2527bacbb59d6c`, the fixture digest above and
execution/evidence specification SHA-256
`51f11db0305585efba81cd99054bd6bd0ae1b87d84cc0a7c8a844879a7e64c5d`.
The runner never downloads or modifies that checkout. Reports retain all cases
and attempts, expected/actual values, errors, unsupported contracts, source
HEAD and dirty state, toolchain and evidence limits. Eleven schema vectors
and the mutation-validation vector are not executed. Output creation is
exclusive with mode 0600; existing files, symlinks and source repository
destinations are refused. Modeled matches are not production conformance,
security clearance, signing approval or release qualification.
