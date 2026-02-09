#!/bin/bash

# 점검 내용 : 안전한 SNMP 버전(v3 이상) 사용 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_59=0

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-59] 점검 시작: 안전한 SNMP 버전 사용"

# [Step 1] SNMP 서비스 구동 여부 우선 확인
if ! systemctl is-active --quiet snmpd; then
    echo "▶ 결과: [ 양호 ] SNMP 서비스가 구동 중이지 않습니다."
    U_59=0
else
    echo "▶ SNMP 서비스 구동 중: 설정 확인 진입"
    
    # [Step 2] snmpd.conf 내 SNMPv3 설정 확인
    # 가이드 사례: createUser, rouser 등 v3 전용 설정 존재 여부 확인
    SNMPD_CONF="/etc/snmp/snmpd.conf"
    
    if [ -f "$SNMPD_CONF" ]; then
        # v3 사용자 설정 확인
        V3_CHECK=$(grep -E "createUser|rouser|authPriv" "$SNMPD_CONF" | grep -v "^#")
        
        # v1, v2c 커뮤니티 설정 확인 (취약 요인)
        V1_V2_CHECK=$(grep -E "rocommunity|rwcommunity|com2sec" "$SNMPD_CONF" | grep -v "^#")

        if [ -n "$V3_CHECK" ] && [ -z "$V1_V2_CHECK" ]; then
            echo "  - 결과: [ 양호 ] SNMP v3 설정이 확인되었으며 하위 버전 설정이 없습니다."
            echo "  - 설정 내용: $V3_CHECK"
            U_59=0
        elif [ -n "$V1_V2_CHECK" ]; then
            echo "  - 결과: [ 취약 ] SNMP v1/v2c 관련 설정이 발견되었습니다. (스니핑 위험)"
            echo "  - 발견된 설정: $(echo "$V1_V2_CHECK" | head -n 1)..."
            U_59=1
            VULN_FLAGS="U_59"
        else
            echo "  - 결과: [ 취약 ] 안전한 SNMP v3 설정이 확인되지 않습니다."
            U_59=1
            VULN_FLAGS="U_59"
        fi
    else
        echo "  - 결과: [ 취약 ] 서비스는 구동 중이나 설정 파일을 찾을 수 없습니다."
        U_59=1
        VULN_FLAGS="U_59"
    fi
fi

echo ""
echo "----------------------------------------------------"
echo "U_59 : $U_59"

# 최종 판정
# 판단 기준: SNMP 서비스를 v3 이상으로 사용하는 경우 양호
if [ $U_59 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $VULN_FLAGS"
fi

exit $FINAL_RESULT
