#!/bin/bash

# 점검 내용 : SNMP 서비스 사용 시 특정 호스트만 접속 허용 여부 점검
# 대상 : Ubuntu 24.04.3 (계열 확인 후 해당 로직만 실행)

U_61=0  # 단일 플래그 사용
VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-61] 점검 시작: SNMP Access Control 설정"

SNMPD_CONF="/etc/snmp/snmpd.conf"

# 1. SNMP 서비스 및 설정 파일 존재 확인
if ! systemctl is-active --quiet snmpd 2>/dev/null && [ ! -f "$SNMPD_CONF" ]; then
    echo "▶ 결과: SNMP 서비스가 구동 중이지 않거나 설정 파일이 없습니다. [ 양호 ]"
    U_61=0
else
    # 2. 시스템 계열 확인 및 분기 실행
    if [ -f /etc/debian_version ]; then
        echo "▶ 감지된 시스템: Debian 계열 (Ubuntu 포함)"
        echo "▶ 가이드 사례 [Debian 계열] 점검 수행 중..."
        
        # rocommunity/rwcommunity 설정 뒤에 특정 IP 주소가 있는지 확인
        # 주소가 없거나 default, 0.0.0.0인 경우 취약
        DEBIAN_ACL=$(grep -E "^rocommunity|^rwcommunity" "$SNMPD_CONF" 2>/dev/null | grep -v "^#")
        
        if [ -n "$DEBIAN_ACL" ]; then
            VULN_FOUND=0
            while read -r line; do
                ADDR=$(echo "$line" | awk '{print $3}')
                if [ -z "$ADDR" ] || [[ "$ADDR" == "default" ]] || [[ "$ADDR" == "0.0.0.0/0" ]]; then
                    VULN_FOUND=1
                    echo "  - 취약 설정 발견: $line"
                fi
            done <<< "$DEBIAN_ACL"

            [ $VULN_FOUND -eq 1 ] && U_61=1
        fi

    elif [ -f /etc/redhat-release ]; then
        echo "▶ 감지된 시스템: Redhat 계열 (CentOS, RHEL 포함)"
        echo "▶ 가이드 사례 [Redhat 계열] 점검 수행 중..."
        
        # com2sec 설정에서 source 필드가 default(모두 허용)인지 확인
        REDHAT_ACL=$(grep "^com2sec" "$SNMPD_CONF" 2>/dev/null | grep -v "^#" | grep "default")
        
        [ -n "$REDHAT_ACL" ] && U_61=1
    else
        echo "▶ 경고: 시스템 계열을 판별할 수 없습니다. 수동 점검이 필요합니다."
        U_61=1
    fi
fi

echo "----------------------------------------------------"
echo "U_61 : $U_61"

# 3. 최종 판정
if [ $U_61 -eq 0 ]; then
    echo "최종 점검 결과: [ 양호 ]"
else
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정: SNMP 접근 제어(ACL) 설정이 미비합니다."
fi

exit $U_61
