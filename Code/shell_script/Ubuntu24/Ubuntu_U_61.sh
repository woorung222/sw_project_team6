#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : SNMP 서비스 사용 시 특정 호스트만 접속 허용 여부 점검
# 대상 : Ubuntu 24.04.3 (계열 확인 후 해당 로직만 실행)

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_61_1 : SNMP 접근 제어(ACL) 설정 미흡 여부
U_61_1=0

# --- 3. 점검 로직 수행 ---

SNMPD_CONF="/etc/snmp/snmpd.conf"

# 1. SNMP 서비스 및 설정 파일 존재 확인
# 서비스가 구동 중이거나 설정 파일이 존재하는 경우 점검 수행
if systemctl is-active --quiet snmpd || [ -f "$SNMPD_CONF" ]; then

    # 2. 시스템 계열 확인 및 분기 실행
    if [ -f /etc/debian_version ]; then
        # [Debian/Ubuntu 계열]
        # rocommunity/rwcommunity 설정 뒤에 특정 IP 주소가 있는지 확인
        if [ -f "$SNMPD_CONF" ]; then
            # grep 결과를 루프 돌며 확인
            while read -r line; do
                [ -z "$line" ] && continue
                
                # 3번째 필드(Source IP) 추출
                ADDR=$(echo "$line" | awk '{print $3}')
                
                # IP가 없거나, default, 0.0.0.0 대역인 경우 취약
                if [ -z "$ADDR" ] || [[ "$ADDR" == "default" ]] || [[ "$ADDR" == "0.0.0.0/0" ]] || [[ "$ADDR" == "0.0.0.0" ]]; then
                    U_61_1=1
                    break
                fi
            done < <(grep -E "^rocommunity|^rwcommunity" "$SNMPD_CONF" 2>/dev/null | grep -v "^#")
        fi

    elif [ -f /etc/redhat-release ]; then
        # [Redhat/CentOS 계열]
        # com2sec 설정에서 source 필드가 default(모두 허용)인지 확인
        if grep "^com2sec" "$SNMPD_CONF" 2>/dev/null | grep -v "^#" | grep -q "default"; then
            U_61_1=1
        fi
    else
        # 계열 확인 불가 시 (보수적으로 취약 처리하거나, 원본 로직 유지)
        U_61_1=1
    fi
else
    # 서비스 미구동 및 설정 파일 없음 -> 양호
    U_61_1=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_61_1" -eq 1 ]; then
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
    "flag_id": "U-61",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_61_1": $U_61_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
