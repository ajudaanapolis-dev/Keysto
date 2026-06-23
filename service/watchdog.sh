#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PID_FILE="$ROOT_DIR/service/keystone-web.pid"
LOG_FILE="$ROOT_DIR/service/keystone-web.log"
PORT="${1:-8080}"

while true
do
  "$ROOT_DIR/service/run-web.sh" "$PORT" >>"$LOG_FILE" 2>&1 &
  PID=$!
  printf '%s\n' "$PID" >"$PID_FILE"
  wait "$PID" || true
  sleep 2
done
