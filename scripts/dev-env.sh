#!/usr/bin/env bash
# CAU development environment. Sourced, so it cannot set -e. audit:ok
#   source scripts/dev-env.sh
#
# Toolchain was installed without root:
#   go        -> ~/.local/go
#   libyara   -> ~/.local/yara  (headers + libyara.a extracted from libyara-dev)
#
# On a normal system with `apt install libyara-dev`, PKG_CONFIG_PATH is unnecessary
# because /usr/lib/*/pkgconfig/yara.pc is already on the default search path.

export PATH="$HOME/.local/go/bin:$PATH"
export PKG_CONFIG_PATH="$HOME/.local/yara/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CGO_ENABLED=1

# go-yara requires cgo + libyara. Without this the build fails with a confusing
# "package yara was not found in the pkg-config search path" error.
export LD_LIBRARY_PATH="$HOME/.local/yara/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
