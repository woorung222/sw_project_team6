#!/usr/bin/env bash
set -u

# =========================================================
# U_11 (상) /etc/syslog.conf 또는 rsyslog 설정파일 권한 설정 | Ubuntu 24.04 (Debian 계열)
# - (일반 PDF 기준) 로그 설정파일(예: syslog/rsyslog)의 소유자 root 및 권한 적정(그룹/기타 쓰기 금지)
# - Ubuntu 24.04: rsyslog 사용이 일반적이며, 설정은 /etc/rsyslog.conf 및 /etc/rsyslog.d/*.conf
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_11_1)
# =========================================================

# -------------------------
# Meta
# -------------------------
HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_11"
CATEGORY="log"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_11_1=1  # 기본은 보수적으로 취약

# -------------------------
# Evidence (내부 판단용: 출력하지 않음)
# -------------------------
ALL_OK=1
ANY_TARGET=0

# -------------------------
# Helper
# -------------------------
stat_val() { stat -c "$1" "$2" 2>/dev/null || true; }

# group/other write 포함 여부(권한 숫자 기준)
has_write_perm_go() {
  local mode="$1"
  [[ "$mode" =~ ^[0-9]{3,4}$ ]] || return 0
  local go="${mode: -2}"
  local g="${go:0:1}"
  local o="${go:1:1}"
  # 2,3,6,7이면 write 포함
  if [[ "$g" =~ [2367] ]] || [[ "$o" =~ [2367] ]]; then
    return 1
  fi
  return 0
}

check_file_owner_perm() {
  # $1: file path
  # return: 0=OK, 1=NOT OK
  local f="$1"
  [ -f "$f" ] || return 0  # 없으면 검사대상 아님(OK)
  ANY_TARGET=1

  local u m
  u="$(stat_val '%U' "$f")"
  m="$(stat_val '%a' "$f")"

  # 소유자 root 권장/요구
  [ "$u" = "root" ] || return 1

  # 권한: group/other write 금지 + 644 이하 권장
  if [ -z "${m:-}" ] || ! [[ "$m" =~ ^[0-9]{3,4}$ ]]; then
    return 1
  fi
  if has_write_perm_go "$m"; then
    return 1
  fi
  [ "$m" -le 644 ] || return 1

  return 0
}

# -------------------------
# 1) 대상 파일/디렉터리
# -------------------------
# 전통 syslog 설정
TARGETS=(
  "/etc/syslog.conf"
  "/etc/rsyslog.conf"
)

RSYSLOG_DIR="/etc/rsyslog.d"

# -------------------------
# 2) 설정파일 점검
# - 존재하는 파일만 검사(없으면 넘어감)
# -------------------------
for f in "${TARGETS[@]}"; do
  if ! check_file_owner_perm "$f"; then
    ALL_OK=0
  fi
done

if [ -d "$RSYSLOG_DIR" ]; then
  # 디렉터리 자체 권한도 보수적으로 점검(소유자 root, group/other write 금지)
  ANY_TARGET=1
  DU="$(stat_val '%U' "$RSYSLOG_DIR")"
  DM="$(stat_val '%a' "$RSYSLOG_DIR")"
  if [ "$DU" != "root" ] || [ -z "${DM:-}" ] || ! [[ "$DM" =~ ^[0-9]{3,4}$ ]]; then
    ALL_OK=0
  else
    if has_write_perm_go "$DM"; then
      ALL_OK=0
    fi
  fi

  # 내부 *.conf 파일 권한 점검
  while IFS= read -r -d '' ff; do
    if ! check_file_owner_perm "$ff"; then
      ALL_OK=0
      break
    fi
  done < <(find "$RSYSLOG_DIR" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null || true)
fi

# -------------------------
# 3) 판정 (flag 1개)
# 양호(FLAG=0) 조건:
# - (대상 설정이 존재하면) 소유자/권한 적정
# - 대상이 전혀 없으면(해당 방식 미사용) 양호로 간주(설정파일 위험 없음)
# -------------------------
if [ "$ALL_OK" -eq 1 ]; then
  FLAG_U_11_1=0
else
  FLAG_U_11_1=1
fi

# -------------------------
# 4) VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_11_1" -eq 1 ]; then
  IS_VUL=1
else
  IS_VUL=0
fi

# -------------------------
# 5) Output (JSON: 필요한 필드만)
# -------------------------
cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_11_1": $FLAG_U_11_1
    },
    "timestamp": "$DATE"
  }
}
EOF

