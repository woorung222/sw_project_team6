#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : Secondary Name Server로만 Zone 정보 전송 제한 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_50_1 : Zone Transfer 제한 설정 (allow-transfer) 검증
U_50_1=0

# --- 3. 점검 로직 수행 ---

# DNS 설정 파일 탐색
NAMED_CONF=""
if [ -f "/etc/bind/named.conf.options" ]; then
    NAMED_CONF="/etc/bind/named.conf.options"
elif [ -f "/etc/named.conf" ]; then
    NAMED_CONF="/etc/named.conf"
elif [ -f "/etc/bind/named.conf" ]; then
    NAMED_CONF="/etc/bind/named.conf"
fi

if [ -n "$NAMED_CONF" ]; then
    # allow-transfer 설정 확인 (주석 제외)
    ALLOW_TRANSFER=$(grep "allow-transfer" "$NAMED_CONF" | grep -v "^#")
    
    if [ -n "$ALLOW_TRANSFER" ]; then
        # 설정은 존재하나 'any'가 포함되어 있으면 취약
        if echo "$ALLOW_TRANSFER" | grep -q "any"; then
            U_50_1=1
        fi
    else
        # allow-transfer 설정 자체가 없으면 취약 (기본 허용 위험)
        U_50_1=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_50_1" -eq 1 ]; then
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
    "flag_id": "U-50",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_50_1": $U_50_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
