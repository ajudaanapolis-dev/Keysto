#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
STATE_DIR="$ROOT_DIR/service"
SUP_PID_FILE="$STATE_DIR/keystone-web-supervisor.pid"
APP_PID_FILE="$STATE_DIR/keystone-web.pid"
LOG_FILE="$STATE_DIR/keystone-web.log"
PORT="${KEYSTONE_WEB_PORT:-8080}"

is_running() {
  [ -f "$1" ] || return 1
  PID=$(cat "$1" 2>/dev/null || true)
  [ -n "${PID:-}" ] || return 1
  kill -0 "$PID" 2>/dev/null
}

start() {
  mkdir -p "$STATE_DIR"
  if is_running "$SUP_PID_FILE"; then
    echo "service already running"
    exit 0
  fi
  python3 - "$ROOT_DIR" "$PORT" "$LOG_FILE" "$SUP_PID_FILE" <<'PY'
import os
import subprocess
import sys

root, port, log_file, pid_file = sys.argv[1:]
log = open(log_file, "ab", buffering=0)
proc = subprocess.Popen(
    [f"{root}/service/watchdog.sh", port],
    stdin=subprocess.DEVNULL,
    stdout=log,
    stderr=log,
    start_new_session=True,
    close_fds=True,
)
with open(pid_file, "w", encoding="utf-8") as fh:
    fh.write(str(proc.pid))
PY
  sleep 1
  echo "started supervisor PID $(cat "$SUP_PID_FILE") on port $PORT"
}

stop() {
  if is_running "$SUP_PID_FILE"; then
    kill "$(cat "$SUP_PID_FILE")" 2>/dev/null || true
    rm -f "$SUP_PID_FILE"
  fi
  if is_running "$APP_PID_FILE"; then
    kill "$(cat "$APP_PID_FILE")" 2>/dev/null || true
    rm -f "$APP_PID_FILE"
  fi
  echo "stopped"
}

status() {
  if is_running "$SUP_PID_FILE"; then
    echo "supervisor: running (PID $(cat "$SUP_PID_FILE"))"
  else
    echo "supervisor: stopped"
  fi
  if is_running "$APP_PID_FILE"; then
    echo "app: running (PID $(cat "$APP_PID_FILE"))"
  else
    echo "app: stopped"
  fi
  echo "log: $LOG_FILE"
}

logs() {
  touch "$LOG_FILE"
  tail -n 60 "$LOG_FILE"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  logs) logs ;;
  *)
    echo "usage: $0 {start|stop|restart|status|logs}"
    exit 1
    ;;
esac
