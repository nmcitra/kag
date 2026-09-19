#!/usr/bin/env bash
# What must never be tracked here. Source only; the rest stays in working repos.
set -euo pipefail
cd "$(dirname "$0")/.."

bad=0
while IFS= read -r f; do
  case "$f" in
    *.htm|*.html) echo "generated reader: $f"; bad=1 ;;
    *transcript*|*TRANSCRIPT*) echo "transcript: $f"; bad=1 ;;
    superpowers/*|*/superpowers/*|plans/*|*/plans/*) echo "plan folder: $f"; bad=1 ;;
    *.bundle|*evidence*bundle*|*.tar|*.tar.gz|*.zip) echo "bundle/archive: $f"; bad=1 ;;
    *.pem|*.key|*.p12|*.pfx|*.env|.env.*|*credentials*|*secret*) echo "credential-shaped: $f"; bad=1 ;;
    .venv/*|venv/*|__pycache__/*|*.pyc|*.exe|*.so|*.dylib|*.test|*.log|*.bak|*~|*.orig) echo "build/scratch output: $f"; bad=1 ;;
  esac
done < <(git ls-files)

# Files above 1 MiB are almost never source.
while IFS= read -r f; do
  sz=$(wc -c < "$f" 2>/dev/null || echo 0)
  if [ "$sz" -gt 1048576 ]; then echo "over 1 MiB, is this source? $f ($sz bytes)"; bad=1; fi
done < <(git ls-files)

if [ "$bad" -ne 0 ]; then
  echo; echo "Hygiene check failed. Source, tests, docs and provenance only."; exit 1
fi
echo "Hygiene: clean ($(git ls-files | wc -l | tr -d ' ') tracked files)"
