#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : NTP 및 시각 동기화 설정 여부 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_65_1=0  # NTP (Ubuntu 24.04에서는 기본 서비스인 systemd-timesyncd 포함 점검)
U_65_2=0  # Chrony 동기화 상태

echo "----------------------------------------------------"
echo "[U-65] 점검 시작: NTP 및 시각 동기화 설정"

# [U_65_1] NTP 서비스 및 동기화 상태 점검 (가이드 순서 1번)
# Ubuntu 24.04는 ntp 데몬 대신 systemd-timesyncd를 기본 시각 동기화 도구로 사용함
echo "[점검 항목 1] NTP/Timesyncd 동기화 상태 확인"
NTP_ACTIVE=$(sudo systemctl is-active ntp 2>/dev/null)
TIMESYNC_ACTIVE=$(sudo systemctl is-active systemd-timesyncd 2>/dev/null)

if [[ "$NTP_ACTIVE" == "active" ]]; then
    # ntpq 명령어를 통해 동기화 상태(시작 부분의 *) 확인
    NTP_SYNC=$(sudo ntpq -p 2>/dev/null | grep "^\*")
    if [ -n "$NTP_SYNC" ]; then
        echo "▶ NTP 결과: [ 양호 ] NTP 서버와 정상 동기화 중입니다."
        U_65_1=0
    else
        echo "▶ NTP 결과: [ 취약 ] NTP 서비스 가동 중이나 동기화되지 않았습니다."
        U_65_1=1
    fi
elif [[ "$TIMESYNC_ACTIVE" == "active" ]]; then
    # timedatectl status를 통해 시스템 클럭 동기화 여부 확인
    TIMESYNC_CHECK=$(sudo timedatectl status | grep "System clock synchronized: yes")
    if [ -n "$TIMESYNC_CHECK" ]; then
        echo "▶ Timesyncd 결과: [ 양호 ] 시스템 클럭이 정상 동기화되었습니다."
        U_65_1=0
    else
        echo "▶ Timesyncd 결과: [ 취약 ] Timesyncd 가동 중이나 동기화되지 않았습니다."
        U_65_1=1
    fi
else
    echo "▶ NTP/Timesyncd 결과: [ 정보 ] 활성화된 기본 동기화 서비스가 없습니다."
    U_65_1=1
fi

echo ""

# [U_65_2] Chrony 서비스 및 동기화 상태 점검 (가이드 순서 2번)
# 최신 리눅스 환경에서 권장되는 Chrony 동기화 상태를 점검함
echo "[점검 항목 2] Chrony 동기화 상태 확인"
CHRONY_ACTIVE=$(sudo systemctl is-active chrony 2>/dev/null)

if [[ "$CHRONY_ACTIVE" == "active" ]]; then
    # chronyc sources 명령에서 ^* (동기화 중) 표시 확인
    CHRONY_SYNC=$(sudo chronyc sources 2>/dev/null | grep "^\^\*")
    if [ -n "$CHRONY_SYNC" ]; then
        echo "▶ Chrony 결과: [ 양호 ] 외부 NTP 서버와 정상 동기화 중입니다."
        U_65_2=0
    else
        echo "▶ Chrony 결과: [ 취약 ] 서비스 가동 중이나 동기화 서버가 없습니다."
        U_65_2=1
    fi
else
    echo "▶ Chrony 결과: [ 정보 ] Chrony 서비스가 비활성화 상태입니다."
    U_65_2=1
fi

echo "----------------------------------------------------"

# 각각의 점검 결과(플래그) 출력
echo "U_65_1 : $U_65_1"
echo "U_65_2 : $U_65_2"

# 최종 판정: 가이드에 따라 두 방식 중 하나라도 정상 동기화 중이면 양호로 간주함
if [[ $U_65_1 -eq 0 || $U_65_2 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
fi

exit $FINAL_RESULT
