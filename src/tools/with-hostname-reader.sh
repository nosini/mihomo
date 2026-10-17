#!/bin/sh
# Build/test with an independently versioned optional reader, without changing
# the ordinary module graph. The caller supplies the feature/test build tags.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
usage() {
    echo "Usage: $0 (--reader-dir DIR | --reader-version VERSION) build|test|vet|list [go flags/packages...]" >&2
    exit 2
}
[ "$#" -ge 3 ] || usage
mode=$1
reader=$2
shift 2
case "$mode" in
    --reader-dir)
        reader=$(CDPATH= cd -- "$reader" && pwd)
        [ -f "$reader/go.mod" ] || usage
        ;;
    --reader-version)
        case "$reader" in v[0-9]*) ;; *) usage ;; esac
        ;;
    *) usage ;;
esac
command=$1
shift
case "$command" in build|test|vet|list) ;; *) usage ;; esac
# Build artifacts belong under the checkout unless the caller supplies an
# absolute project-specific scratch directory. Never inherit another workspace.
build_root=${HOSTNAME_BUILD_DIR:-"$root/bin/hostname-reader"}
case "$build_root" in /*) ;; *) echo "HOSTNAME_BUILD_DIR must be absolute" >&2; exit 2 ;; esac
mkdir -p "$build_root"
run=$(mktemp -d "$build_root/module.XXXXXXXX")
trap 'rm -f -- "$run/go.mod" "$run/go.sum"; rmdir -- "$run"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp "$root/go.mod" "$run/go.mod"
cp "$root/go.sum" "$run/go.sum"
cd "$root"
export GOWORK=off
# The optional reader uses the observer's Go baseline. Ordinary builds keep
# their original Go baseline and dependency versions.
go mod edit -modfile="$run/go.mod" -go=1.25.0
module=github.com/nosini/socketowner/hostname
case "$mode" in
    --reader-dir)
        go mod edit -modfile="$run/go.mod" -require="$module@v0.0.0" -replace="$module=$reader"
        ;;
    --reader-version)
        go mod edit -modfile="$run/go.mod" -require="$module@$reader"
        ;;
esac
go "$command" -modfile="$run/go.mod" -mod=mod "$@"
