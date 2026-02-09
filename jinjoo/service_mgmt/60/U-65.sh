#!/bin/bash

# 점검 내용 : 서버 시각 동기화 설정 및 가동 여부 점검
# 대상 : Ubuntu 24.04.3 (가이드 [NTP] 사례 적용)

U_65=0  # 단일 플래그 사용 (인덱스 제거)
VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-65] 점검 시작: NTP 및 시각 동기화 설정"

# [NTP] 점검 진입
echo ""
echo "[NTP - 서비스 활성화 여부 점검]"

# 가이드 사례 명령어 적용: systemctl list-units --type=service | grep ntp
# Ubuntu 24.04의 경우 ntp, chrony, systemd-timesyncd 중 하나가 구동됨을 고려
echo "▶ 가이드 명령어 실행: systemctl list-units --type=service | grep ntp"
NTP_SERVICE_CHECK=$(sudo systemctl list-units --type=service | grep -Ei "ntp|chrony|timesyncd")

if [ -n "$NTP_SERVICE_CHECK" ]; then
    echo "  - 감지된 서비스 정보: "
    echo "$NTP_SERVICE_CHECK"
    
    # 가이드의 목적대로 서비스가 실제 'running' 상태인지 확인
    if echo "$NTP_SERVICE_CHECK" | grep -q "running"; then
        echo "▶ 결과: [ 양호 ] NTP 관련 서비스가 활성화되어 정상 구동 중입니다."
        U_65=0
    else
        echo "▶ 결과: [ 취약 ] NTP 관련 서비스가 목록에는 있으나 구동(running) 상태가 아닙니다."
        U_65=1
        VULN_FLAGS="U_65"
    fi
else
    echo "▶ 결과: [ 취약 ] systemctl 결과에 ntp 관련 서비스가 발견되지 않았습니다."
    U_65=1
    VULN_FLAGS="U_65"
fi

echo ""
echo "----------------------------------------------------"
echo "U_65 : $U_65"

# 최종 판정
if [ $U_65 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그: $VULN_FLAGS"
fi

exit $FINAL_RESULT
