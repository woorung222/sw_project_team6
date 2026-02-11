#!/bin/bash

# [U-18] /etc/shadow 파일 소유자 및 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-18"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_18_1=0; IS_VUL=0

# [U_18_1] /etc/shadow 점검
FILE="/etc/shadow"
CHECK_FILE=$(run_cmd "[U_18_1] $FILE 존재 여부 확인" "ls $FILE 2>/dev/null || echo '파일 없음'")

if [[ -f "$FILE" ]]; then
    U=$(run_cmd "[U_18_1] $FILE 소유자 확인" "stat -c '%U' '$FILE'")
    M=$(run_cmd "[U_18_1] $FILE 권한 확인" "stat -c '%a' '$FILE'")
    
    # 기준: 소유자 root, 권한 640 이하 (기타 권한은 반드시 0)
    if [[ "$U" == "root" ]] && [[ "$M" -le 640 ]] && [[ "${M: -1}" == "0" ]]; then
        log_basis "[U_18_1] $FILE 설정 양호 (소유자: $U, 권한: $M)" "양호"
    else
        U_18_1=1
        log_basis "[U_18_1] $FILE 설정 미흡 (소유자: $U, 권한: $M)" "취약"
    fi
else
    U_18_1=1
    log_basis "[U_18_1] /etc/shadow 파일이 존재하지 않아 취약함" "취약"
fi

IS_VUL=$U_18_1

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
      "U_18_1": $U_18_1
    },
    "timestamp": "$DATE"
  }
}
EOF