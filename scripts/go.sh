#!/bin/sh
set -eu
DR4C_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export GOMODCACHE="$DR4C_ROOT/.venv/go/modcache"
export GOCACHE="$DR4C_ROOT/.venv/go/buildcache"
export GOTOOLCHAIN="${DR4C_GO_TOOLCHAIN:-local}"
exec go "$@"
