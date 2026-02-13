#!/bin/bash

# [U-44] tftp, talk 서비스 비활성화 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : tftp, talk, ntalk 서비스가 비활성화되어 있는 경우 양호
# DB 정합성 : IS_AUTO=1 (자동화 스크립트 적용)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_44_1=0 # inetd
U_44_2=0 # xinetd
U_44_3=0 # systemd/process
IS_VUL=0
IS_AUTO=1 

TARGET_SVCS="tftp|talk|ntalk"

# 1) [U_44_1] inetd.conf 점검
if [ -f "/etc/inetd.conf" ]; then
    if grep -v "^#" /etc/inetd.conf | grep -iE "$TARGET_SVCS" >/dev/null 2>&1; then
        U_44_1=1
    fi
fi

# 2) [U_44_2] xinetd.d 점검
if [ -d "/etc/xinetd.d" ]; then
    if grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$TARGET_SVCS" | grep -iw "no" >/dev/null 2>&1; then
        U_44_2=1
    fi
fi

# 3) [U_44_3] systemd 및 프로세스 점검
# 유닛 상태 확인
if systemctl list-units --type service,socket 2>/dev/null | grep -E "$TARGET_SVCS" | grep -w "active" >/dev/null 2>&1; then
    U_44_3=1
fi
# 프로세스 확인
if [ "$U_44_3" -eq 0 ]; then
    if ps -ef | grep -v "grep" | grep -iE "tftpd|talkd|ntalkd" >/dev/null 2>&1; then
        U_44_3=1
    fi
fi

[ "$U_44_1" -eq 1 ] || [ "$U_44_2" -eq 1 ] || [ "$U_44_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-44",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_44_1": $U_44_1, "U_44_2": $U_44_2, "U_44_3": $U_44_3 },
    "timestamp": "$DATE"
  }
}
EOF