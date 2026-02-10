#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : tftp, talk, ntalk 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_44_1 : [1. /etc/inetd.conf] 내 tftp, talk, ntalk 설정 여부
# U_44_2 : [2. /etc/xinetd.d/] 내 tftp, talk, ntalk 설정 여부
# U_44_3 : [3. systemd] 유닛 활성화 여부
U_44_1=0
U_44_2=0
U_44_3=0

# 점검 서비스 리스트
TFTP_TALK_SERVICES="tftp|talk|ntalk"

# --- 3. 점검 로직 수행 ---

# [Step 1] 1. /etc/inetd.conf 설정 확인
if [ -f "/etc/inetd.conf" ]; then
    INETD_TFTP=$(sudo grep -v "^#" /etc/inetd.conf | grep -iE "$TFTP_TALK_SERVICES")
    if [ -n "$INETD_TFTP" ]; then
        U_44_1=1
    fi
fi

# [Step 2] 2. /etc/xinetd.d/ 설정 확인
if [ -d "/etc/xinetd.d" ]; then
    XINETD_TFTP=$(sudo grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iE "$TFTP_TALK_SERVICES")
    if [ -n "$XINETD_TFTP" ]; then
        U_44_2=1
    fi
fi

# [Step 3] 3. systemd 서비스 유닛 확인
# 서비스 유닛이 enabled 상태인지 점검
SYSTEMD_TFTP=$(systemctl list-unit-files 2>/dev/null | grep -iE "$TFTP_TALK_SERVICES" | grep "enabled")

if [ -n "$SYSTEMD_TFTP" ]; then
    U_44_3=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_44_1" -eq 1 ] || [ "$U_44_2" -eq 1 ] || [ "$U_44_3" -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- 5. JSON 출력 (Stdout) ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP_ADDR",
    "user": "$CURRENT_USER"
  },
  "result": {
    "flag_id": "U-44",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_44_1": $U_44_1,
      "U_44_2": $U_44_2,
      "U_44_3": $U_44_3
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
