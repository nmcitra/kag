#!/usr/bin/env bash
# Local, offline, package-only draft qualification report. Nonzero is expected
# while required production contracts remain unsupported.
set -euo pipefail
fixture=
digest=
report=
profile=
seen_fixture=0
seen_digest=0
seen_report=0
seen_profile=0
usage() {
  echo "usage: run-conformance.sh --fixture LOCAL_FILE --fixture-sha256 FIXED_SHA256 --report NEW_ABSOLUTE_PATH [--profile-root LOCAL_CHECKOUT]" >&2
}
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || { usage; exit 2; }
  [ -n "$2" ] || { usage; exit 2; }
  case "$1" in
    --fixture) [ "$seen_fixture" -eq 0 ] || exit 2; fixture=$2; seen_fixture=1 ;;
    --fixture-sha256) [ "$seen_digest" -eq 0 ] || exit 2; digest=$2; seen_digest=1 ;;
    --report) [ "$seen_report" -eq 0 ] || exit 2; report=$2; seen_report=1 ;;
    --profile-root) [ "$seen_profile" -eq 0 ] || exit 2; profile=$2; seen_profile=1 ;;
    *) usage; exit 2 ;;
  esac
  shift 2
done
[ "$seen_fixture" -eq 1 ] && [ "$seen_digest" -eq 1 ] && [ "$seen_report" -eq 1 ] || { usage; exit 2; }
[ "$digest" = "732e293673461807d9ae491ac3d00b1c42dbb4143c5b3bf6056ab3d44993f25d" ] || { echo "fixed fixture digest required" >&2; exit 2; }
# Resolve caller-relative inputs before moving to the package repository.
case "$fixture" in /*) ;; *) fixture="$PWD/$fixture" ;; esac
if [ -n "$profile" ]; then
  case "$profile" in /*) ;; *) profile="$PWD/$profile" ;; esac
fi
case "$report" in /*) ;; *) echo "report requires an absolute path" >&2; exit 2 ;; esac
cd "$(dirname "$0")/.."
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GIT_OPTIONAL_LOCKS=0
export KAG_CONFORMANCE_RUN_FIXTURE="$fixture"
export KAG_CONFORMANCE_REPORT="$report"
export KAG_CONFORMANCE_PROFILE_ROOT="$profile"
exec go test ./internal/execution -run '^TestConformanceQualification$' -count=1 -v
