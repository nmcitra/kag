# Contributing to KAG

Thanks for being here. This is a small repository with a maintainer who
built it and a host who keeps it alive. The rules are few and they exist so
the code stays something other people can build on.

## The rules

1. **One PR per change.** A PR that carries two changes gets split.
2. **DCO sign-off on every commit.** Add `Signed-off-by: Your Name <you@example.com>`
   (`git commit -s`). It says you wrote the change or are entitled to
   contribute it. It names a person, never a tool.
3. **Green checks before review.** CI runs the DCO check, the hygiene check,
   and the tests. Run `scripts/check-all.sh` locally first.
4. **No product names.** KIL is vendor-neutral. Adapters for a specific
   product live in a separate repository.
5. **Source only.** No generated readers, transcripts, plan folders, evidence
   bundles, credentials, or runtime state. The hygiene check refuses them.
6. **Pin KTP by tag.** Say which release of `ktp-rfc` a change builds against.
7. **State evidence limits.** Modeled, observed, or validated. A passing test
   is not a conformance claim; a conformance claim comes from a tagged
   release running the published vectors.

## Process

- Fork, branch from `main`, make the change, sign off, open a PR using the
  template.
- A first PR from a new contributor has its CI held until a maintainer
  approves the run. That's GitHub, not us; it goes away after the first
  merge.
- `main` takes PRs only: green checks, linear history, no force pushes.

## Provenance

`NOTICE` and `PROVENANCE.md` record where the code came from and who wrote
it. If you import code from elsewhere, append to `PROVENANCE.md`; don't
rewrite it.

## License

Contributions are licensed under Apache-2.0, the same as the project.
