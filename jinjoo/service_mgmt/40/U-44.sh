#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : tftp, talk, ntalk 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_44_1=0  # [1. /etc/inetd.conf] 내 tftp, talk, ntalk 설정 여부
U_44_2=0  # [2. /etc/xinetd.d/] 내 tftp, talk, ntalk 설정 여부
U_44_3=0  # [3. systemd] 유닛 활성화 여부

VULN_FLAGS=""

# 점검 서비스 리스트
TFTP_TALK_SERVICES="tftp|talk|ntalk"

echo "----------------------------------------------------"
echo "[U-44] 점검 시작: tftp, talk, ntalk 서비스 비활성화"

# [Step 1] 1. /etc/inetd.conf 설정 확인
echo "[Step 1] /etc/inetd.conf 내 tftp, talk, ntalk 확인"
if [ -f "/etc/inetd.conf" ]; then
    INETD_TFTP=$(sudo grep -v "^#" /etc/inetd.conf | grep -iE "$TFTP_TALK_SERVICES")
    if [ -n "$INETD_TFTP" ]; then
        echo "▶ 1. /etc/inetd.conf: [ 취약 ] 취약 서비스 설정이 발견되었습니다."
        U_44_1=1; VULN_FLAGS="$VULN_FLAGS U_44_1"
    else
        echo "▶ 1. /etc/inetd.conf: [ 양호 ]"
    fi
else
    echo "▶ 1. /etc/inetd.conf: [ 양호 ] (파일 미존재)"
fi

# [Step 2] 2. /etc/xinetd.d/ 설정 확인
echo ""
echo "[Step 2] /etc/xinetd.d/ 내 tftp, talk, ntalk 확인"
if [ -d "/etc/xinetd.d" ]; then
    XINETD_TFTP=$(sudo grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iE "$TFTP_TALK_SERVICES")
    if [ -n "$XINETD_TFTP" ]; then
        echo "▶ 2. /etc/xinetd.d/: [ 취약 ] 취약 서비스 설정이 발견되었습니다."
        U_44_2=1; VULN_FLAGS="$VULN_FLAGS U_44_2"
    else
        echo "▶ 2. /etc/xinetd.d/: [ 양호 ]"
    fi
else
    echo "▶ 2. /etc/xinetd.d/: [ 양호 ] (디렉터리 미존재)"
fi

# [Step 3] 3. systemd 서비스 유닛 확인
echo ""
echo "[Step 3] systemd 내 tftp, talk, ntalk 활성화 확인"
# 서비스 유닛이 enabled 상태인지 점검
SYSTEMD_TFTP=$(systemctl list-unit-files 2>/dev/null | grep -iE "$TFTP_TALK_SERVICES" | grep "enabled")

if [ -n "$SYSTEMD_TFTP" ]; then
    echo "▶ 3. systemd: [ 취약 ] 활성화된 서비스 유닛이 발견되었습니다."
    echo "  - 발견된 유닛: $(echo "$SYSTEMD_TFTP" | awk '{print $1}' | xargs)"
    U_44_3=1; VULN_FLAGS="$VULN_FLAGS U_44_3"
else
    echo "▶ 3. systemd: [ 양호 ]"
fi

echo "----------------------------------------------------"
echo "U_44_1 : $U_44_1"
echo "U_44_2 : $U_44_2"
echo "U_44_3 : $U_44_3"

# 최종 판정
# 판단 기준: tftp, talk, ntalk 서비스가 비활성화 되어 있는 경우 양호
if [[ $U_44_1 -eq 0 && $U_44_2 -eq 0 && $U_44_3 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
