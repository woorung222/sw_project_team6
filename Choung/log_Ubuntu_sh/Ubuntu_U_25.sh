#!/bin/bash

# [U-25] world writable 파일 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-25"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_25_1=0; IS_VUL=0

# 제외 경로 설정 (성능 및 오탐 방지)
PRUNE_EXPR="-path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune"

# 1. world writable 파일 검색 (U_25_1)
FOUND_WW=$(run_cmd "[U_25_1] world writable 파일 검색" "find / $PRUNE_EXPR -o -type f -perm -2 -print -quit 2>/dev/null")

if [[ -n "$FOUND_WW" ]]; then
    U_25_1=1
    log_basis "[U_25_1] 시스템에 world writable 파일이 존재함 (예: $FOUND_WW)" "취약"
else
    log_basis "[U_25_1] 불필요한 world writable 파일이 발견되지 않음" "양호"
fi

IS_VUL=$U_25_1

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
      "U_25_1": $U_25_1
    },
    "timestamp": "$DATE"
  }
}
EOF
