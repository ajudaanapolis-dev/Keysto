#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
export PATH="/root/snap/codex/34/.cargo/bin:/root/snap/codex/34/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"

if [ -x "$ROOT_DIR/tools/zigcc" ]; then
  LINKER="$ROOT_DIR/tools/zigcc"
elif command -v cc >/dev/null 2>&1; then
  LINKER="$(command -v cc)"
elif command -v clang >/dev/null 2>&1; then
  LINKER="$(command -v clang)"
else
  echo "error: no suitable linker found; provide tools/zigcc, cc, or clang" >&2
  exit 1
fi

export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$LINKER"
if [ "${RUSTFLAGS:-}" = "" ]; then
  export RUSTFLAGS="-C linker=$LINKER"
else
  export RUSTFLAGS="$RUSTFLAGS -C linker=$LINKER"
fi

exec /root/snap/codex/34/.cargo/bin/cargo "$@"
