# Versioning

Tags are the version. `main` is where the code lives.

## Tags

Bare, numeric, semantic: `vMAJOR.MINOR.PATCH`. **A published tag is never moved or deleted.** A mistake in a tagged release is fixed by a new release that says so.

Before `v1.0.0`, minors may break: `0.y.z` means pre-conformance. **`v1.0.0` is reserved for the first tag that runs the adopted KTP conformance suite green** and says so in its release notes. Green has a meaning here: the runner feeds each case's own inputs to the implementation, with no lookup tables or hardcoded results. Where a case hands the implementation a fact as a flag (a binding matched, a source authenticated, nothing was sent), the real check is its own entry in `claims.yaml`, with its evidence state, until it is built and shown.

## What a tag carries

A GitHub Release with notes stating which KTP release it implements, which KIL release it depends on, the conformance runner's output attached, and checksums beside any built artifact. Tags are signed by the maintainer.

## Pinning

Reference this project by tag. Reference KTP by tag; state it in the release notes and in `otcs.yaml` under `implements`. Between tags, `main` may carry material no tag contains; if you build against it, pin the exact commit and say so. A commit is a fixed point; `main` is not.

## Dependencies

`go.mod` and `go.sum` committed. Dependabot proposes updates; the maintainer reviews them like any PR.
