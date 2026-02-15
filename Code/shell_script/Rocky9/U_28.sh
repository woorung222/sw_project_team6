#!/bin/bash

# [U-28] 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : TCP Wrapper, Iptables, Firewalld, UFW 중 하나라도 적절한 접근 제어가 설정되어 있으면 양호
# DB 정합성 : IS_AUTO=0 (관리자 접속 차단 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (1: 미설정/취약 상태로 시작)
U_28_1=1 # TCP Wrapper
U_28_2=1 # Iptables
U_28_3=1 # Firewalld
U_28_4=1 # UFW
IS_AUTO=0

# 1. [U_28_1] TCP Wrapper 점검
if [ -f "/etc/hosts.deny" ] && grep -vE '^#|^\s#' /etc/hosts.deny | grep -iwq "ALL: ALL"; then
    U_28_1=0
fi

# 2. [U_28_2] Iptables 점검
if command -v iptables >/dev/null 2>&1; then
    if [ $(iptables -L INPUT -n | grep -vE "^Chain|^target|^$|policy" | wc -l) -gt 0 ]; then
        U_28_2=0
    fi
fi

# 3. [U_28_3] Firewalld 점검
if systemctl is-active --quiet firewalld 2>/dev/null; then
    U_28_3=0
fi

# 4. [U_28_4] UFW 점검
if command -v ufw >/dev/null 2>&1 && ufw status | grep -iq "Status: active"; then
    U_28_4=0
fi

# 최종 결과: 하나라도 양호(0)하면 IS_VUL=0
IS_VUL=1
if [ "$U_28_1" -eq 0 ] || [ "$U_28_2" -eq 0 ] || [ "$U_28_3" -eq 0 ] || [ "$U_28_4" -eq 0 ]; then
    IS_VUL=0
fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-28",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_28_1": $U_28_1, "U_28_2": $U_28_2, "U_28_3": $U_28_3, "U_28_4": $U_28_4 },
    "timestamp": "$DATE"
  }
}
EOF