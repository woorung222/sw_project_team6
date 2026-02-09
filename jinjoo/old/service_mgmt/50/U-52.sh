#!/bin/bash

# 점검 내용 : 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_52_1=0  # [inetd] Telnet 서비스 활성화 여부
U_52_2=0  # [xinetd] Telnet 서비스 활성화 여부
U_52_3=0  # [systemd] Telnet 서비스 활성화 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-52] 점검 시작: Telnet 서비스 비활성화"

# 1. [inetd] 점검
echo ""
echo "[1. inetd 점검]"
if [ -f "/etc/inetd.conf" ]; then
    echo "▶ [inetd] 진입: /etc/inetd.conf 내 Telnet 설정 확인"
    # 주석 처리되지 않은 telnet 설정 확인
    TELNET_INETD=$(grep -i "telnet" /etc/inetd.conf | grep -v "^#")
    if [ -n "$TELNET_INETD" ]; then
        echo "  - 결과: [ 취약 ] Telnet 서비스가 활성화되어 있습니다."
        echo "  - 설정 내용: $TELNET_INETD"
        U_52_1=1; VULN_FLAGS="$VULN_FLAGS U_52_1"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [inetd] 진입: 설정 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 2. [xinetd] 점검
echo ""
echo "[2. xinetd 점검]"
if [ -f "/etc/xinetd.d/telnet" ]; then
    echo "▶ [xinetd] 진입: /etc/xinetd.d/telnet 내 disable 설정 확인"
    # disable 옵션이 no로 되어 있는지 확인
    XINETD_CHECK=$(grep -i "disable" /etc/xinetd.d/telnet | grep -i "no")
    if [ -n "$XINETD_CHECK" ]; then
        echo "  - 결과: [ 취약 ] Telnet 서비스가 활성화(disable = no)되어 있습니다."
        U_52_2=1; VULN_FLAGS="$VULN_FLAGS U_52_2"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [xinetd] 진입: 설정 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 3. [systemd] 점검
echo ""
echo "[3. systemd 점검]"
echo "▶ [systemd] 진입: Telnet 소켓 및 서비스 활성화 확인"
# telnet.socket 유닛 리스트 확인
SYSTEMD_TELNET=$(systemctl list-units --type=socket 2>/dev/null | grep -i "telnet")
if [ -n "$SYSTEMD_TELNET" ]; then
    echo "  - 결과: [ 취약 ] Telnet 소켓/서비스가 활성화되어 있습니다."
    echo "  - 상세 정보: $SYSTEMD_TELNET"
    U_52_3=1; VULN_FLAGS="$VULN_FLAGS U_52_3"
else
    echo "  - 결과: [ 양호 ]"
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_52_1:$U_52_1, U_52_2:$U_52_2, U_52_3:$U_52_3"

# 최종 판정
# 판단 기준: 원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우 양호
if [[ $U_52_1 -eq 0 && $U_52_2 -eq 0 && $U_52_3 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
