#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : DoS 공격에 이용 가능한 서비스(echo, discard, daytime, chargen, ntp, snmp, dns, smtp) 비활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_38_1 : [/etc/inetd.conf] 내 취약 서비스 활성 여부
# U_38_2 : [/etc/xinetd.d/] 내 취약 서비스 활성 여부
# U_38_3 : [systemd] 유닛 활성화 여부
# U_38_4 : [Port] 포트(7, 9, 13, 19, 123, 161, 53, 25) 오픈 여부
U_38_1=0
U_38_2=0
U_38_3=0
U_38_4=0

# 점검 서비스 키워드 정의
DOS_SERVICES="echo|discard|daytime|chargen|ntp|snmp|dns|named|bind|smtp|sendmail|postfix"
# 점검 포트 정의 (7, 9, 13, 19, 123, 161, 53, 25)
DOS_PORTS_REGEX=":(7|9|13|19|123|161|53|25) "

# --- 3. 점검 로직 수행 ---

# [Step 1] /etc/inetd.conf 설정 확인
if [ -f "/etc/inetd.conf" ]; then
    INETD_DOS=$(sudo grep -v "^#" /etc/inetd.conf | grep -iE "$DOS_SERVICES")
    if [ -n "$INETD_DOS" ]; then
        U_38_1=1
    fi
fi

# [Step 2] /etc/xinetd.d/ 설정 확인
if [ -d "/etc/xinetd.d" ]; then
    XINETD_DOS=$(sudo grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iE "$DOS_SERVICES")
    if [ -n "$XINETD_DOS" ]; then
        U_38_2=1
    fi
fi

# [Step 3] systemd 서비스 유닛 확인
# ntp, snmp, dns(named/bind), smtp(postfix/sendmail) 유닛 상태 통합 점검
SYSTEMD_DOS=$(systemctl list-unit-files 2>/dev/null | grep -iE "$DOS_SERVICES|chrony" | grep "enabled")
if [ -n "$SYSTEMD_DOS" ]; then
    U_38_3=1
fi

# [Step 4] 실제 오픈된 포트 확인 (TCP/UDP 통합)
DOS_ACTIVE_PORTS=$(sudo netstat -antup 2>/dev/null | grep -E "$DOS_PORTS_REGEX" | grep -E "LISTEN|UDP")
if [ -n "$DOS_ACTIVE_PORTS" ]; then
    U_38_4=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_38_1" -eq 1 ] || [ "$U_38_2" -eq 1 ] || [ "$U_38_3" -eq 1 ] || [ "$U_38_4" -eq 1 ]; then
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
    "flag_id": "U-38",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_38_1": $U_38_1,
      "U_38_2": $U_38_2,
      "U_38_3": $U_38_3,
      "U_38_4": $U_38_4
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
