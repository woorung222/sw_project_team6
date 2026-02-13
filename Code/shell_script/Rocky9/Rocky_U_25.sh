#!/bin/bash

# [U-25] world writable 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 불필요한 world writable 파일이 존재하면 취약
# DB 정합성 : IS_AUTO=0 (광범위한 권한 변경 위험으로 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_25_1=0 
IS_VUL=0
IS_AUTO=0 

# --- 점검 시작 ---
# -xdev: 로컬 파일 시스템만 / -perm -0002: Other Write 권한 / -print -quit: 발견 시 즉시 종료
FOUND_FILE=$(find / -xdev -type f -perm -0002 -print -quit 2>/dev/null)

if [ -n "$FOUND_FILE" ]; then
    U_25_1=1
fi

IS_VUL=$U_25_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-25",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_25_1": $U_25_1 },
    "timestamp": "$DATE"
  }
}
EOF