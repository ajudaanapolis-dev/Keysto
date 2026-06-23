#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PORT="${1:-8080}"

cd "$ROOT_DIR"
exec "$ROOT_DIR/target/release/keystone-btc-proof" serve "0.0.0.0:$PORT"
