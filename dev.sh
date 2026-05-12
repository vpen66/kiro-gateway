#!/usr/bin/env bash
set -euo pipefail

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "${SCRIPT_SOURCE}" ]]; do
  SCRIPT_DIR="$(cd -P "$(dirname "${SCRIPT_SOURCE}")" >/dev/null 2>&1 && pwd)"
  SCRIPT_SOURCE="$(readlink "${SCRIPT_SOURCE}")"
  if [[ "${SCRIPT_SOURCE}" != /* ]]; then
    SCRIPT_SOURCE="${SCRIPT_DIR}/${SCRIPT_SOURCE}"
  fi
done
PROJECT_ROOT="$(cd -P "$(dirname "${SCRIPT_SOURCE}")" >/dev/null 2>&1 && pwd)"
cd "${PROJECT_ROOT}"

APP_MODULE="${APP_MODULE:-main:app}"
DEV_DIR="${KIRO_DEV_DIR:-.dev}"
PID_FILE="${KIRO_DEV_PID_FILE:-${DEV_DIR}/kiro-gateway.pid}"
LOG_FILE="${KIRO_DEV_LOG_FILE:-${DEV_DIR}/kiro-gateway.log}"

if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="${PYTHON}"
elif [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
else
  PYTHON_BIN="python"
fi

usage() {
  cat <<'EOF'
Usage:
  ./dev.sh start [reload]
  ./dev.sh stop
  ./dev.sh restart [reload]
  ./dev.sh status

Behavior:
  start          Start without hot reload. Code changes do not take effect until restart.
  start reload   Start with uvicorn --reload. Code changes trigger automatic reload.
  restart        Restart without hot reload.
  restart reload Restart with hot reload.

Environment:
  SERVER_HOST / SERVER_PORT override host and port.
  PYTHON overrides the Python executable.
  KIRO_DEV_DIR overrides the runtime directory for pid/log files.
EOF
}

config_value() {
  local name="$1"
  "${PYTHON_BIN}" - "$name" <<'PY'
import sys
from kiro import config

print(getattr(config, sys.argv[1]))
PY
}

server_host() {
  if [[ -n "${SERVER_HOST:-}" ]]; then
    printf '%s\n' "${SERVER_HOST}"
  else
    config_value "SERVER_HOST"
  fi
}

server_port() {
  if [[ -n "${SERVER_PORT:-}" ]]; then
    printf '%s\n' "${SERVER_PORT}"
  else
    config_value "SERVER_PORT"
  fi
}

read_pid() {
  if [[ ! -f "${PID_FILE}" ]]; then
    return 1
  fi

  tr -d '[:space:]' < "${PID_FILE}"
}

process_matches_app() {
  local pid="$1"
  local command

  command="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
  [[ "${command}" == *"uvicorn"* && "${command}" == *"${APP_MODULE}"* ]]
}

is_running() {
  local pid

  pid="$(read_pid || true)"
  [[ -n "${pid}" ]] || return 1
  kill -0 "${pid}" 2>/dev/null || return 1
  process_matches_app "${pid}"
}

remove_stale_pid() {
  if [[ -f "${PID_FILE}" ]] && ! is_running; then
    rm -f "${PID_FILE}"
  fi
}

require_start_mode() {
  local mode="${1:-}"

  if [[ -n "${mode}" && "${mode}" != "reload" ]]; then
    echo "Invalid start mode: ${mode}" >&2
    usage >&2
    exit 2
  fi
}

start_server() {
  local mode="${1:-}"
  local host
  local port
  local pid

  require_start_mode "${mode}"
  mkdir -p "${DEV_DIR}"
  remove_stale_pid

  if is_running; then
    pid="$(read_pid)"
    echo "Kiro Gateway is already running (pid=${pid})."
    echo "Log: ${LOG_FILE}"
    exit 1
  fi

  host="$(server_host)"
  port="$(server_port)"

  local command=(
    "${PYTHON_BIN}" -m uvicorn "${APP_MODULE}"
    --host "${host}"
    --port "${port}"
  )

  if [[ "${mode}" == "reload" ]]; then
    command+=(--reload)
  fi

  echo "Starting Kiro Gateway on localhost:${port} (reload=$([[ "${mode}" == "reload" ]] && echo "on" || echo "off"))..."
  echo "Command: ${command[*]}" > "${LOG_FILE}"
  nohup "${command[@]}" >> "${LOG_FILE}" 2>&1 &
  pid="$!"
  echo "${pid}" > "${PID_FILE}"

  sleep 0.5
  if ! is_running; then
    echo "Failed to start Kiro Gateway. See log: ${LOG_FILE}" >&2
    rm -f "${PID_FILE}"
    exit 1
  fi

  echo "Started Kiro Gateway (pid=${pid})."
  echo "Pages: http://localhost:${port}/admin"
  echo "Log: ${LOG_FILE}"
}

stop_server() {
  local pid

  if ! is_running; then
    remove_stale_pid
    echo "Kiro Gateway is not running."
    return 0
  fi

  pid="$(read_pid)"
  echo "Stopping Kiro Gateway (pid=${pid})..."
  kill "${pid}" 2>/dev/null || true

  for _ in {1..50}; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      rm -f "${PID_FILE}"
      echo "Stopped Kiro Gateway."
      return 0
    fi
    sleep 0.1
  done

  echo "Process did not stop gracefully; sending SIGKILL..."
  kill -9 "${pid}" 2>/dev/null || true
  rm -f "${PID_FILE}"
  echo "Stopped Kiro Gateway."
}

status_server() {
  local pid

  if is_running; then
    pid="$(read_pid)"
    echo "Kiro Gateway is running (pid=${pid})."
    echo "Log: ${LOG_FILE}"
    return 0
  fi

  remove_stale_pid
  echo "Kiro Gateway is not running."
  return 1
}

main() {
  local command="${1:-}"
  shift || true

  case "${command}" in
    start)
      start_server "${1:-}"
      ;;
    stop)
      stop_server
      ;;
    restart)
      require_start_mode "${1:-}"
      stop_server
      start_server "${1:-}"
      ;;
    status)
      status_server
      ;;
    help|--help|-h|"")
      usage
      ;;
    *)
      echo "Unknown command: ${command}" >&2
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
