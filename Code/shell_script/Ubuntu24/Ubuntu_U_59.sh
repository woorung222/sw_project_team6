#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 안전한 SNMP 버전(v3 이상) 사용 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_59_1 : SNMP 서비스 활성화 및 v3 설정 적절성 여부
U_59_1=0

# --- 3. 점검 로직 수행 ---

# [Step 1] SNMP 서비스 구동 여부 확인
# systemctl is-active --quiet : 활성 상태면 0(성공), 아니면 0이 아님
if systemctl is-active --quiet snmpd; then
    # 서비스가 구동 중인 경우 설정 파일 점검
    SNMPD_CONF="/etc/snmp/snmpd.conf"
    
    if [ -f "$SNMPD_CONF" ]; then
        # v3 사용자 설정 확인 (createUser, rouser, authPriv)
        if grep -E "createUser|rouser|authPriv" "$SNMPD_CONF" | grep -v "^#" > /dev/null; then
            V3_EXISTS=1
        else
            V3_EXISTS=0
        fi
        
        # v1, v2c 커뮤니티 설정 확인 (rocommunity, rwcommunity, com2sec)
        if grep -E "rocommunity|rwcommunity|com2sec" "$SNMPD_CONF" | grep -v "^#" > /dev/null; then
            V1_V2_EXISTS=1
        else
            V1_V2_EXISTS=0
        fi

        # 판정: v3 설정이 있고 동시에 v1/v2 설정이 없어야 안전
        if [ "$V3_EXISTS" -eq 1 ] && [ "$V1_V2_EXISTS" -eq 0 ]; then
            U_59_1=0
        else
            # v3 설정이 없거나, v1/v2 설정이 남아있는 경우 취약
            U_59_1=1
        fi
    else
        # 서비스는 구동 중이나 설정 파일이 없는 경우 (관리 부재로 간주)
        U_59_1=1
    fi
else
    # 서비스가 구동 중이지 않음 (양호)
    U_59_1=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_59_1" -eq 1 ]; then
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
    "flag_id": "U-59",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_59_1": $U_59_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
