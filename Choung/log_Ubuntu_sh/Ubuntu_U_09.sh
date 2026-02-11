#!/bin/bash

# [U-09] /etc/hosts 파일 소유자 및 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U_09"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_09_1=1; IS_VUL=0

# 1. /etc/hosts 점검 (U_09_1)
HOSTS_FILE="/etc/hosts"
if [[ -f "$HOSTS_FILE" ]]; then
    H_USER=$(run_cmd "[U_09_1] $HOSTS_FILE 소유자 확인" "stat -c '%U' '$HOSTS_FILE'")
    H_MODE=$(run_cmd "[U_09_1] $HOSTS_FILE 권한 확인" "stat -c '%a' '$HOSTS_FILE'")

    # 소유자 root, 권한 644 이하
    if [[ "$H_USER" == "root" ]] && [[ "$H_MODE" -le 644 ]] && [[ ! "$H_MODE" =~ [2367]$ ]]; then
        U_09_1=0
        log_basis "[U_09_1] $HOSTS_FILE 설정 양호" "양호"
    else
        U_09_1=1
        log_basis "[U_09_1] $HOSTS_FILE 설정 미흡" "취약"
    fi
else
    log_basis "[U_09_1] $HOSTS_FILE 파일 없음 (양호)" "양호"
    U_09_1=0
fi

IS_VUL=$U_09_1

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_09_1": $U_09_1
    },
    "timestamp": "$DATE"
  }
}
EOF
