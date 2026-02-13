#!/bin/bash

# [U-52] Telnet 서비스 비활성화 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : Telnet 서비스가 비활성화되어 있고 관련 프로세스가 구동되지 않는 경우 양호
# DB 정합성 : IS_AUTO=1 (자동화 스크립트 적용)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_52_1=0; U_52_2=0; U_52_3=0; U_52_4=0
IS_VUL=0
IS_AUTO=1 

# Telnet 서버 패키지 설치 여부 확인
if rpm -qa | grep -qE "telnet-server|krb5-telnet"; then
    # 1. [U_52_1] inetd 점검
    if [ -f "/etc/inetd.conf" ] && grep -v "^#" /etc/inetd.conf | grep -iw "telnet" >/dev/null 2>&1; then
        U_52_1=1
    fi

    # 2. [U_52_2] xinetd 점검
    if [ -f "/etc/xinetd.d/telnet" ] && grep -i "disable" /etc/xinetd.d/telnet | grep -iw "no" >/dev/null 2>&1; then
        U_52_2=1
    fi

    # 3. [U_52_3] systemd 점검
    if systemctl is-active --quiet telnet.socket 2>/dev/null || systemctl is-active --quiet telnet.service 2>/dev/null; then
        U_52_3=1
    fi
fi

# 4. [U_52_4] 프로세스 점검 (패키지 여부와 상관없이 실제 구동 확인)
if ps -ef | grep -v "grep" | grep -iE "telnetd|in.telnetd" >/dev/null 2>&1; then
    U_52_4=1
fi

[ "$U_52_1" -eq 1 ] || [ "$U_52_2" -eq 1 ] || [ "$U_52_3" -eq 1 ] || [ "$U_52_4" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-52",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_52_1": $U_52_1, "U_52_2": $U_52_2, "U_52_3": $U_52_3, "U_52_4": $U_52_4 },
    "timestamp": "$DATE"
  }
}
EOF