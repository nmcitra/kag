#!/usr/bin/env bash
# Run what CI runs, in the same order. The one command before opening a PR.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$1"; }

step "Hygiene"
bash scripts/check-hygiene.sh

step "DCO sign-off on commits not yet on main"
base=$(git merge-base HEAD origin/main 2>/dev/null || git rev-list --max-parents=0 HEAD | tail -1)
missing=0
while IFS= read -r sha; do
  if ! git log -1 --format=%B "$sha" | grep -q '^Signed-off-by: .* <.*>'; then
    echo "missing Signed-off-by: $(git log -1 --format='%h %s' "$sha")"; missing=1
  fi
done < <(git rev-list --no-merges "$base"..HEAD 2>/dev/null)
[ "$missing" -eq 0 ] && echo "DCO: all commits signed off" || exit 1

step "Go: format, vet, test, race"
if [ -f go.mod ]; then
  test -z "$(gofmt -l .)" || { echo "gofmt: these files need formatting:"; gofmt -l .; exit 1; }
  go vet ./...
  go test ./...
  go test -race ./...
else
  echo "no go.mod yet"
fi

printf '\nAll gates green.\n'
