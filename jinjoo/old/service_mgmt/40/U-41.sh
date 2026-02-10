#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : automountd(autofs) 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

U_41_1=0  # Step 1: 현재 실행 중인 automountd 프로세스 점검
U_41_2=0  # Step 2: 시스템 시작 시 자동 실행 설정(부팅 시 활성화) 점검

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-41] 점검 시작: 불필요한 automountd 제거"

# [Step 1] automountd 서비스 실행 여부 확인
# 명령어: ps -ef | grep automount
echo "[Step 1] automountd 프로세스 가동 상태 확인"
AUTOMOUNT_PS=$(ps -ef | grep -iE "automount|autofs" | grep -v "grep")

if [ -n "$AUTOMOUNT_PS" ]; then
    echo "▶ 프로세스: [ 활성 ] 서비스가 현재 메모리에서 구동 중입니다."
    U_41_1=1
    VULN_FLAGS="$VULN_FLAGS U_41_1"
else
    echo "▶ 프로세스: [ 비활성 ]"
fi


# [Step 2] 시작 스크립트 내 서비스 활성 여부 확인
# 명령어: ls -l /etc/rc*.d/* | grep amd
echo ""
echo "[Step 2] 시작 스크립트 및 서비스 유닛 설정 확인"

# 2-1. 가이드 명시: rc.d 스크립트 확인
RC_CHECK=$(ls -l /etc/rc*.d/S* 2>/dev/null | grep -E "amd|autofs")

# 2-2. 현대적 기준: systemd 유닛 상태 확인
SYSTEMD_CHECK=$(systemctl list-unit-files 2>/dev/null | grep -iE "autofs|automount" | grep "enabled")

if [ -n "$RC_CHECK" ] || [ -n "$SYSTEMD_CHECK" ]; then
    echo "▶ 시작 설정: [ 활성 ] 부팅 시 서비스가 자동 실행되도록 설정되어 있습니다."
    U_41_2=1
    VULN_FLAGS="$VULN_FLAGS U_41_2"
else
    echo "▶ 시작 설정: [ 비활성 ]"
fi

echo "----------------------------------------------------"
echo "U_41_1 : $U_41_1"
echo "U_41_2 : $U_41_2"

# 최종 판정
# 양호 기준: 서비스가 비활성화된 경우 (둘 다 0이어야 함)
if [[ $U_41_1 -eq 0 && $U_41_2 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
