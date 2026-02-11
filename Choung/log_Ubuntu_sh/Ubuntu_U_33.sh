#!/bin/bash

# [U-33] 숨겨진 파일 및 디렉토리 검색 및 제거
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-33"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_33_1=0; IS_VUL=0

# 제외 경로 (성능 및 오탐 방지)
PRUNE_EXPR="-path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o -path /var/lib -prune -o -path /snap -prune"

# 1. [U_33_1] 숨겨진 파일/디렉터리 검색
HIDDEN_FILES=$(run_cmd "[U_33_1] 숨겨진 파일 검색" "find / $PRUNE_EXPR -o -type f -name '.*' -print -quit 2>/dev/null")
if [[ -n "$HIDDEN_FILES" ]]; then
    U_33_1=1
    log_basis "[U_33_1] 숨겨진 파일 발견됨 (예: $HIDDEN_FILES)" "취약"
fi

if [[ $U_33_1 -eq 0 ]]; then
    HIDDEN_DIRS=$(run_cmd "[U_33_1] 숨겨진 디렉터리 검색" "find / $PRUNE_EXPR -o -type d -name '.*' -print -quit 2>/dev/null")
    if [[ -n "$HIDDEN_DIRS" ]]; then
        U_33_1=1
        log_basis "[U_33_1] 숨겨진 디렉터리 발견됨 (예: $HIDDEN_DIRS)" "취약"
    fi
fi

if [[ $U_33_1 -eq 0 ]]; then
    log_basis "[U_33_1] 의심스러운 숨겨진 파일/디렉터리 미발견" "양호"
fi

IS_VUL=$U_33_1

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
      "U_33_1": $U_33_1
    },
    "timestamp": "$DATE"
  }
}
EOF
