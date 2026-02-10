#!/bin/bash

# 점검 내용 : SNMP Community String의 복잡성 설정 여부 점검
# 대상 : Ubuntu 24.04.3 (계열 확인 후 해당 로직만 실행)

U_60=0  # 단일 플래그 사용
VULN_FLAGS=""

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

echo "----------------------------------------------------"
echo "[U-60] 점검 시작: SNMP Community String 복잡성 설정"

SNMPD_CONF="/etc/snmp/snmpd.conf"

# 1. SNMP 설정 파일 존재 확인
if [ ! -f "$SNMPD_CONF" ]; then
    echo "▶ 결과: SNMP 설정 파일($SNMPD_CONF)이 존재하지 않습니다. [ 양호 ]"
    U_60=0
else
    # 2. 시스템 계열 확인 및 분기 실행
    if [ -f /etc/debian_version ]; then
        echo "▶ 감지된 시스템: Debian 계열 (Ubuntu 포함)"
        echo "▶ 가이드 사례 [Debian 계열] 점검 수행 중..."
        
        # rocommunity/rwcommunity 설정 확인 (2번째 인자가 community)
        COMMS=$(grep -E "^rocommunity|^rwcommunity" "$SNMPD_CONF" 2>/dev/null | grep -v "^#" | awk '{print $2}')
        
        if [ -n "$COMMS" ]; then
            for comm in $COMMS; do
                if ! check_snmp_complexity "$comm"; then
                    echo "  - 발견된 취약 문자열: $comm"
                    U_60=1
                    break
                fi
            done
        fi

    elif [ -f /etc/redhat-release ]; then
        echo "▶ 감지된 시스템: Redhat 계열 (CentOS, RHEL 포함)"
        echo "▶ 가이드 사례 [Redhat 계열] 점검 수행 중..."
        
        # com2sec 설정 확인 (4번째 인자가 community)
        COMMS=$(grep "^com2sec" "$SNMPD_CONF" 2>/dev/null | grep -v "^#" | awk '{print $4}')
        
        if [ -n "$COMMS" ]; then
            for comm in $COMMS; do
                if ! check_snmp_complexity "$comm"; then
                    echo "  - 발견된 취약 문자열: $comm"
                    U_60=1
                    break
                fi
            done
        fi
    else
        echo "▶ 경고: 시스템 계열을 판별할 수 없습니다. 수동 점검이 필요합니다."
        U_60=1
    fi
fi

echo "----------------------------------------------------"
echo "U_60 : $U_60"

# 3. 최종 판정
if [ $U_60 -eq 0 ]; then
    echo "최종 점검 결과: [ 양호 ]"
else
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정: SNMP Community String이 복잡성 기준을 만족하지 않습니다."
fi

exit $U_60
