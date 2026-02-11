#!/bin/bash

# [U-26] /dev에 존재하지 않는 device 파일 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-26"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_26_1=0; IS_VUL=0

# 1. /dev 내 일반 파일 검색 (U_26_1)
# 디바이스 디렉터리 내에 캐릭터/블록 장치가 아닌 일반 파일이 있는지 확인
FOUND_DEV_FILE=$(run_cmd "[U_26_1] /dev 내 비인가 일반 파일 점검" "find /dev -type f -print -quit 2>/dev/null")

if [[ -n "$FOUND_DEV_FILE" ]]; then
    U_26_1=1
    log_basis "[U_26_1] /dev 디렉터리에 device 파일이 아닌 일반 파일이 존재함 (예: $FOUND_DEV_FILE)" "취약"
else
    log_basis "[U_26_1] /dev 디렉터리 내 장치 파일 관리 상태 양호" "양호"
fi

IS_VUL=$U_26_1

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
      "U_26_1": $U_26_1
    },
    "timestamp": "$DATE"
  }
}
EOF
