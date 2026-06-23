#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
LOG_DIR="$ROOT_DIR/service/tunnel"
LOG_FILE="$LOG_DIR/cloudflared.log"
PID_FILE="$LOG_DIR/cloudflared.pid"

mkdir -p "$LOG_DIR"

start() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "tunnel already running"
    exit 0
  fi
  : > "$LOG_FILE"
  python3 - "$ROOT_DIR" "$LOG_FILE" "$PID_FILE" <<'PY'
import os
import subprocess
import sys

root, log_file, pid_file = sys.argv[1:]
log = open(log_file, "ab", buffering=0)
proc = subprocess.Popen(
    [f"{root}/tools/cloudflared", "tunnel", "--url", "http://127.0.0.1:8080"],
    stdin=subprocess.DEVNULL,
    stdout=log,
    stderr=log,
    start_new_session=True,
    close_fds=True,
)
with open(pid_file, "w", encoding="utf-8") as fh:
    fh.write(str(proc.pid))
PY
  sleep 4
  echo "started tunnel PID $(cat "$PID_FILE")"
}

stop() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
  fi
  echo "stopped"
}

status() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "running PID $(cat "$PID_FILE")"
  else
    echo "stopped"
  fi
}

url() {
  python3 - "$LOG_FILE" <<'PY'
import re
import sys
from pathlib import Path

log = Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore")
matches = re.findall(r'https://[a-zA-Z0-9.-]+trycloudflare\\.com', log)
if matches:
    print(matches[-1])
else:
    sys.exit(1)
PY
}

logs() {
  tail -n 80 "$LOG_FILE"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  url) url ;;
  logs) logs ;;
  *)
    echo "usage: $0 {start|stop|restart|status|url|logs}"
    exit 1
    ;;
esac
