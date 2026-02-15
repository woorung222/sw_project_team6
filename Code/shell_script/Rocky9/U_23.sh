#!/bin/bash

# [U-23] SUID, SGID, Sticky bit 설정 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 주요 불필요 대상 파일에 SUID/SGID가 설정된 경우 취약

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_23_1=0 
IS_VUL=0
IS_AUTO=0 

# 점검 대상 파일 목록 (불필요한 SUID/SGID 권고 목록)
CHECK_FILES=(
    "/sbin/dump" "/usr/sbin/dump"
    "/sbin/restore" "/usr/sbin/restore"
    "/usr/bin/at"
    "/usr/bin/lpq" "/usr/bin/lpr" "/usr/bin/lprm"
    "/usr/sbin/lpc" "/usr/bin/newgrp"
    "/usr/sbin/traceroute"
)

# 점검 로직
for FILE in "${CHECK_FILES[@]}"; do
    if [ -f "$FILE" ]; then
        # SUID(4000) 또는 SGID(2000)가 설정되어 있는지 확인
        PERM=$(stat -c "%a" "$FILE")
        if [ $((PERM & 06000)) -ne 0 ]; then
            U_23_1=1
            break
        fi
    fi
done

IS_VUL=$U_23_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-23",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_23_1": $U_23_1 },
    "timestamp": "$DATE"
  }
}
EOF