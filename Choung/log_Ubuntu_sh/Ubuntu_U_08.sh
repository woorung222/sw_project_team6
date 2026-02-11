#!/bin/bash

# [U-08] /etc/shadow 파일 소유자 및 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-08"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_08_1=1; IS_VUL=0

# 1. /etc/shadow 점검 (U_08_1)
SHADOW_FILE="/etc/shadow"
if [[ -f "$SHADOW_FILE" ]]; then
    S_USER=$(run_cmd "[U_08_1] $SHADOW_FILE 소유자 확인" "stat -c '%U' '$SHADOW_FILE'")
    S_MODE=$(run_cmd "[U_08_1] $SHADOW_FILE 권한 확인" "stat -c '%a' '$SHADOW_FILE'")

    # 소유자 root, 기타(other) 권한 0
    if [[ "$S_USER" == "root" ]] && [[ "${S_MODE: -1}" == "0" ]]; then
        U_08_1=0
        log_basis "[U_08_1] $SHADOW_FILE 설정 양호 (소유자: $S_USER, 권한: $S_MODE)" "양호"
    else
        U_08_1=1
        log_basis "[U_08_1] $SHADOW_FILE 설정 미흡 (소유자: $S_USER, 권한: $S_MODE)" "취약"
    fi
else
    log_step "[U_08_1] 파일 확인" "ls $SHADOW_FILE" "파일 없음"
    U_08_1=1
fi

IS_VUL=$U_08_1

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
      "U_08_1": $U_08_1
    },
    "timestamp": "$DATE"
  }
}
EOF
