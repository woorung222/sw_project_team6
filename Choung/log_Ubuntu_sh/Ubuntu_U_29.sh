#!/bin/bash

# [U-29] hosts.lpd 파일 소유자 및 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-29"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_29_1=0; IS_VUL=0

# 1. [U_29_1] hosts.lpd 점검
FILE="/etc/hosts.lpd"
CHECK_FILE=$(run_cmd "[U_29_1] $FILE 존재 여부 확인" "ls $FILE 2>/dev/null || echo '없음'")

if [[ -f "$FILE" ]]; then
    U=$(run_cmd "[U_29_1] $FILE 소유자 확인" "stat -c '%U' '$FILE'")
    M=$(run_cmd "[U_29_1] $FILE 권한 확인" "stat -c '%a' '$FILE'")
    
    # 소유자 root, 권한 600 (원본 로직: -eq 600)
    if [[ "$U" == "root" ]]; then
        if [[ "$M" -eq 600 ]]; then
            log_basis "[U_29_1] $FILE 설정 양호 (소유자: $U, 권한: $M)" "양호"
        else
            U_29_1=1
            log_basis "[U_29_1] $FILE 권한($M)이 600이 아님" "취약"
        fi
    else
        U_29_1=1
        log_basis "[U_29_1] $FILE 소유자($U)가 root가 아님" "취약"
    fi
else
    log_basis "[U_29_1] /etc/hosts.lpd 파일이 존재하지 않음 (양호)" "양호"
fi

IS_VUL=$U_29_1

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
      "U_29_1": $U_29_1
    },
    "timestamp": "$DATE"
  }
}
EOF
