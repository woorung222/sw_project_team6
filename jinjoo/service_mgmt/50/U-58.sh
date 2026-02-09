#!/bin/bash

# 점검 내용 : SNMP 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_58=0

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-58] 점검 시작: 불필요한 SNMP 서비스 구동 점검"

# [Step 1] SNMP 서비스 활성화 여부 확인
# 가이드 사례 명령어: systemctl list-units --type=service | grep snmpd
echo "▶ [LINUX] 진입: SNMP 서비스(snmpd) 활성화 여부 확인"

# loaded active running 상태인 유닛 확인
SNMPD_STATUS=$(systemctl list-units --type=service 2>/dev/null | grep snmpd)

if [ -n "$SNMPD_STATUS" ]; then
    echo "  - 결과: [ 취약 ] 불필요한 SNMP 서비스가 활성화(active) 중입니다."
    echo "  - 상세 정보: $SNMPD_STATUS"
    U_58=1
    VULN_FLAGS="U_58"
else
    # 서비스가 활성화되어 있지 않거나 설치되지 않은 경우
    echo "  - 결과: [ 양호 ] SNMP 서비스가 활성화되어 있지 않습니다."
    U_58=0
fi

echo ""
echo "----------------------------------------------------"
echo "U_58 : $U_58"

# 최종 판정
# 판단 기준: SNMP 서비스를 사용하지 않는 경우 양호
if [ $U_58 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $VULN_FLAGS"
fi

exit $FINAL_RESULT
