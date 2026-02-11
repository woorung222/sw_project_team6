#!/usr/bin/env bash
# common_logging.sh

set -u

# ISO-8601 with timezone (+0900)
ts() { date "+%Y-%m-%dT%H:%M:%S%z"; }

# JSONL 1줄 출력용 escape
json_escape_1line() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  s="${s//$'\t'/\\t}"
  echo -n "$s"
}

_log_flag_id() { echo -n "${FLAG_ID:-UNKNOWN}"; }

# [진단 내용] 점검 명령/결과 기록
log_step() {
  local title="${1:-}" cmd="${2:-}" result="${3:-}"
  echo "{\"ts\":\"$(ts)\",\"flag_id\":\"$(_log_flag_id)\",\"section\":\"[진단 내용]\",\"title\":\"$(json_escape_1line "$title")\",\"cmd\":\"$(json_escape_1line "$cmd")\",\"result\":\"$(json_escape_1line "$result")\"}" >&2
}

# [진단 결과] 진단 근거 기록 (수정됨: basis + status 분리)
# usage: log_basis "근거 문장" "판정(양호/취약)"
log_basis() {
  local basis="${1:-}"
  local status="${2:-info}"
  echo "{\"ts\":\"$(ts)\",\"flag_id\":\"$(_log_flag_id)\",\"section\":\"[진단 결과]\",\"title\":\"진단 근거\",\"basis\":\"$(json_escape_1line "$basis")\",\"status\":\"$(json_escape_1line "$status")\"}" >&2
}

# 명령 실행 + 결과 캡쳐 + step 로그
run_cmd() {
  local title="$1" cmd="$2" timeout_s="${3:-0}"
  local out="" code=0

  if [[ "$timeout_s" =~ ^[0-9]+$ ]] && [[ "$timeout_s" -gt 0 ]]; then
    out="$(timeout "$timeout_s" bash -lc "$cmd" 2>/dev/null)"
    code=$?
  else
    out="$(bash -lc "$cmd" 2>/dev/null)"
    code=$?
  fi

  log_step "$title" "$cmd" "exit_code=$code, stdout=${out:-<empty>}"
  echo -n "$out"
  return $code
}