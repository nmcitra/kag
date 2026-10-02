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
