#!/bin/bash

# [U-30] UMASK 설정 관리 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : UMASK 값이 022 이상(022, 027 등)으로 설정된 경우 양호

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_30_1=0 # /etc/profile
U_30_2=0 # /etc/login.defs
IS_VUL=0
IS_AUTO=1 

# --- [U_30_1] /etc/profile 점검 ---
if [ -f "/etc/profile" ]; then
    P_UMASK=$(grep -i "^[[:space:]]*umask" /etc/profile | tail -n 1 | awk '{print $2}')
    if [ -z "$P_UMASK" ] || [ "$P_UMASK" -lt 022 ]; then
        U_30_1=1
    fi
fi

# --- [U_30_2] /etc/login.defs 점검 ---
if [ -f "/etc/login.defs" ]; then
    L_UMASK=$(grep -i "^[[:space:]]*UMASK" /etc/login.defs | grep -v "^#" | tail -n 1 | awk '{print $2}')
    if [ -z "$L_UMASK" ] || [ "$L_UMASK" -lt 022 ]; then
        U_30_2=1
    fi
fi

[ "$U_30_1" -eq 1 ] || [ "$U_30_2" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-30",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_30_1": $U_30_1, "U_30_2": $U_30_2 },
    "timestamp": "$DATE"
  }
}
EOF