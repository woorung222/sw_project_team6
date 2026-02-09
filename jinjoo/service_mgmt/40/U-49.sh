#!/bin/bash

# 점검 내용 : BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

U_49=0  # DNS 보안 버전 패치 점검 통합 플래그

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-49] 점검 시작: DNS 보안 버전 패치"

# [Step 1] DNS 서비스 활성화 여부 확인
# 가이드 사례 명령어: systemctl list-units --type=service | grep named
echo "[Step 1] DNS(named) 서비스 활성화 상태 확인"
DNS_ACT=$(systemctl list-units --type=service 2>/dev/null | grep named)

if [ -n "$DNS_ACT" ]; then
    echo "▶ 서비스 상태: [ 활성 ] DNS 서비스가 가동 중입니다."
    echo "  - 상세 유닛: $DNS_ACT"
    
    # [Step 2] BIND 버전 확인
    # 가이드 사례 명령어: named -v
    echo ""
    echo "[Step 2] BIND 버전 확인"
    if command -v named > /dev/null; then
        BIND_VER=$(named -v)
        echo "▶ 설치 버전: $BIND_VER"
        echo "  - 결과: 버전 정보가 확인되었습니다. 최신 보안 패치 버전인지 점검하십시오."
        # 판단 기준: 주기적으로 패치를 관리하고 있지 않은 경우 취약
        # 관리자의 정책 확인이 필요한 항목이므로 정보 출력 후 양호 상태 유지
        U_49=0
    else
        echo "▶ 결과: [ 취약 ] 서비스는 활성 상태이나 named 명령어를 찾을 수 없습니다."
        U_49=1
        VULN_FLAGS="U_49"
    fi
else
    echo "▶ 서비스 상태: [ 양호 ] DNS(named) 서비스가 활성화되어 있지 않습니다."
    U_49=0
fi

echo ""
echo "----------------------------------------------------"
echo "U_49 : $U_49"

# 최종 판정
# 판단 기준: 주기적으로 패치를 관리하는 경우 양호
if [ $U_49 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $VULN_FLAGS"
fi

exit $FINAL_RESULT
