#!/bin/bash

# 점검 내용 : OS 버전 EOL 여부 및 커널 보안 패치 상태 점검
# 대상 : Ubuntu 24.04.3 (지시하신 3단계 로직 적용)

U_64=0
VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-64] 점검 시작: 주기적 보안 패치 및 벤더 권고사항 적용"

# [Step 1] OS 및 커널 버전 확인
echo "▶ [Step 1] 시스템 버전 정보 확인 (hostnamectl)"
OS_INFO=$(sudo hostnamectl)
OS_NAME=$(echo "$OS_INFO" | grep "Operating System" | cut -d: -f2 | xargs)
KERNEL_VER=$(echo "$OS_INFO" | grep "Kernel" | cut -d: -f2 | xargs)

echo "  - OS 명칭: $OS_NAME"
echo "  - 현재 커널: $KERNEL_VER"

# [Step 2] EOL(End of Life) 상태 확인
# Ubuntu 24.04(Noble Numbat)는 현재 지원 기간 내에 있음
echo ""
echo "▶ [Step 2] OS EOL 상태 확인"
# Ubuntu 릴리즈 정보를 통해 지원 종료 여부 판단 (Ubuntu 전용 도구 사용)
if command -v ubuntu-security-status > /dev/null; then
    EOL_CHECK=$(sudo ubuntu-security-status | grep -i "out of support")
    if [ -n "$EOL_CHECK" ]; then
        echo "  - 결과: [ 취약 ] 현재 OS 버전은 EOL(지원 종료) 상태입니다."
        U_64=1
    else
        echo "  - 결과: [ 양호 ] 현재 OS 버전은 제조사 지원 범위 내에 있습니다."
    fi
else
    # 도구가 없을 경우 버전을 직접 비교 (예: 24.04 기준)
    echo "  - [참고] Ubuntu 24.04는 2029년까지 기본 지원되는 LTS 버전입니다."
fi

# [Step 3] 최신 보안 패치가 적용된 Kernel 버전으로 업데이트 여부 확인
echo ""
echo "▶ [Step 3] 커널 및 보안 패치 대기 상태 확인"
# 실제 업데이트가 필요한 보안 패키지 리스트 확인
SECURITY_UPDATES=$(sudo apt-get -s dist-upgrade | grep -i security | wc -l)

if [ "$SECURITY_UPDATES" -gt 0 ]; then
    echo "  - 결과: [ 취약 ] 적용 가능한 보안 패치/커널 업데이트가 존재합니다."
    echo "  - 미적용 보안 패키지 수: $SECURITY_UPDATES 개"
    U_64=1
else
    echo "  - 결과: [ 양호 ] 시스템이 최신 보안 패치 상태를 유지하고 있습니다."
fi

echo ""
echo "----------------------------------------------------"
echo "U_64 : $U_64"

# 최종 판정
if [ $U_64 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정: OS 버전 업그레이드 또는 보안 패치 적용이 필요합니다."
fi

exit $FINAL_RESULT
