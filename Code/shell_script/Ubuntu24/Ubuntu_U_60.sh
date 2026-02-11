#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : SNMP Community String의 복잡성 설정 여부 점검
# 대상 : Ubuntu 24.04.3 (계열 확인 후 해당 로직만 실행)

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_60_1 : SNMP Community String 복잡성 미준수 여부
U_60_1=0

# --- 3. 점검 로직 수행 ---

# 복잡성 체크 함수 (3가지 기준 적용)
check_snmp_complexity() {
    local str=$1
    # 1. 기본값 확인 (public, private)
    if [[ "$str" == "public" || "$str" == "private" ]]; then
        return 1
    fi
    
    # 영문/숫자 외 특수문자 포함 여부 확인
    if [[ "$str" =~ [^a-zA-Z0-9] ]]; then
        # 3. 특수문자 포함 시 8자리 미만이면 취약
        if [ ${#str} -lt 8 ]; then
            return 1
        fi
    else
        # 2. 영문/숫자만 포함 시 10자리 미만이면 취약
        if [ ${#str} -lt 10 ]; then
            return 1
        fi
    fi
    return 0
}

SNMPD_CONF="/etc/snmp/snmpd.conf"

# 1. SNMP 설정 파일 존재 확인
if [ -f "$SNMPD_CONF" ]; then
    # 2. 시스템 계열 확인 및 분기 실행
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu 계열
        # rocommunity/rwcommunity 설정 확인 (2번째 인자가 community)
        COMMS=$(grep -E "^rocommunity|^rwcommunity" "$SNMPD_CONF" 2>/dev/null | grep -v "^#" | awk '{print $2}')
        
        if [ -n "$COMMS" ]; then
            for comm in $COMMS; do
                if ! check_snmp_complexity "$comm"; then
                    U_60_1=1
                    break
                fi
            done
        fi

    elif [ -f /etc/redhat-release ]; then
        # Redhat/CentOS 계열
        # com2sec 설정 확인 (4번째 인자가 community)
        COMMS=$(grep "^com2sec" "$SNMPD_CONF" 2>/dev/null | grep -v "^#" | awk '{print $4}')
        
        if [ -n "$COMMS" ]; then
            for comm in $COMMS; do
                if ! check_snmp_complexity "$comm"; then
                    U_60_1=1
                    break
                fi
            done
        fi
    else
        # 시스템 계열 판별 불가 시 수동 점검 필요 (보수적으로 취약 처리하거나, 로직에 따라 0 처리)
        # 여기서는 스크립트 특성상 확인 불가하므로 0(N/A) 또는 1(Warning) 선택 가능하나,
        # 원본 로직에 따라 1로 처리
        U_60_1=1
    fi
else
    # 파일이 없으면 SNMP 서비스를 사용하지 않는 것으로 간주하여 양호
    U_60_1=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_60_1" -eq 1 ]; then
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
    "flag_id": "U-60",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_60_1": $U_60_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
