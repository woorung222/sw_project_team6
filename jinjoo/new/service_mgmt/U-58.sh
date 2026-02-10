#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : SNMP 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_58_1 : SNMP 서비스(snmpd) 활성화 여부
U_58_1=0

# --- 3. 점검 로직 수행 ---

# [Step 1] SNMP 서비스 활성화 여부 확인
# systemctl list-units 명령으로 snmpd 서비스가 활성(active) 상태인지 확인
# grep -q 옵션을 사용하여 출력 없이 종료 코드만 확인 (찾으면 0 -> true)
if systemctl list-units --type=service 2>/dev/null | grep -q "snmpd"; then
    U_58_1=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_58_1" -eq 1 ]; then
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
    "flag_id": "U-58",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_58_1": $U_58_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
