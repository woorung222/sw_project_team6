#!/bin/bash

# [U-15] 파일 및 디렉터리 소유자 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-15"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_15_1=0; IS_VUL=0

# 제외 경로
PRUNE_EXPR="-path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o -path /snap -prune"

# [U_15_1] 소유자/그룹 없는 파일 검색
FOUND_BAD=$(run_cmd "[U_15_1] 소유자(UID) 또는 그룹(GID) 없는 파일 검색" "find / $PRUNE_EXPR -o \( -nouser -o -nogroup \) -print -quit 2>/dev/null")

if [[ -n "$FOUND_BAD" ]]; then
    U_15_1=1
    log_basis "[U_15_1] 시스템에 소유자 정보가 없는 파일/디렉터리가 존재함 (예: $FOUND_BAD)" "취약"
else
    log_basis "[U_15_1] 소유자 또는 그룹이 없는 파일이 발견되지 않음" "양호"
fi

IS_VUL=$U_15_1

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
      "U_15_1": $U_15_1
    },
    "timestamp": "$DATE"
  }
}
EOF