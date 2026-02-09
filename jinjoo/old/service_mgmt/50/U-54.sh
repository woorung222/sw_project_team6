#!/bin/bash

# 점검 내용 : 암호화되지 않은 FTP 서비스 비활성화 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_54_1=0  # [inetd] FTP 서비스 활성화 여부
U_54_2=0  # [xinetd] FTP 서비스 활성화 여부
U_54_3=0  # [vsFTP] FTP 서비스 활성화 여부
U_54_4=0  # [ProFTP] FTP 서비스 활성화 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-54] 점검 시작: 암호화되지 않는 FTP 서비스 비활성화"

# 1. [inetd] 점검
echo ""
echo "[1. inetd 점검]"
if [ -f "/etc/inetd.conf" ]; then
    echo "▶ [inetd] 진입: /etc/inetd.conf 내 FTP 설정 확인"
    # 주석 처리되지 않은 ftp 서비스 라인 확인
    INETD_FTP=$(grep -i "ftp" /etc/inetd.conf | grep -v "^#")
    if [ -n "$INETD_FTP" ]; then
        echo "  - 결과: [ 취약 ] FTP 서비스가 활성화되어 있습니다."
        echo "  - 설정 내용: $INETD_FTP"
        U_54_1=1; VULN_FLAGS="$VULN_FLAGS U_54_1"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [inetd] 진입: 설정 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 2. [xinetd] 점검
echo ""
echo "[2. xinetd 점검]"
if [ -f "/etc/xinetd.d/ftp" ]; then
    echo "▶ [xinetd] 진입: /etc/xinetd.d/ftp 내 서비스 활성화 여부 확인"
    # disable 옵션이 no이거나 설정되지 않은 경우 확인
    XINETD_CHECK=$(grep -i "disable" /etc/xinetd.d/ftp | grep -i "no")
    if [ -n "$XINETD_CHECK" ]; then
        echo "  - 결과: [ 취약 ] FTP 서비스가 활성화(disable = no)되어 있습니다."
        U_54_2=1; VULN_FLAGS="$VULN_FLAGS U_54_2"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [xinetd] 진입: 설정 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 3. [vsFTP] 점검
echo ""
echo "[3. vsFTP 점검]"
echo "▶ [vsFTP] 진입: 서비스 활성화 여부 확인"
# systemctl 명령으로 vsftpd 서비스 상태 점검
VSFTP_ACT=$(systemctl list-units --type service 2>/dev/null | grep vsftpd)
if [ -n "$VSFTP_ACT" ]; then
    echo "  - 결과: [ 취약 ] vsftpd 서비스가 활성화되어 있습니다."
    echo "  - 상세 정보: $VSFTP_ACT"
    U_54_3=1; VULN_FLAGS="$VULN_FLAGS U_54_3"
else
    echo "  - 결과: [ 양호 ]"
fi

# 4. [ProFTP] 점검
echo ""
echo "[4. ProFTP 점검]"
echo "▶ [ProFTP] 진입: 서비스 활성화 여부 확인"
# systemctl 명령으로 proftpd 서비스 상태 점검
PROFTP_ACT=$(systemctl list-units --type=service 2>/dev/null | grep proftp)
if [ -n "$PROFTP_ACT" ]; then
    echo "  - 결과: [ 취약 ] proftpd 서비스가 활성화되어 있습니다."
    echo "  - 상세 정보: $PROFTP_ACT"
    U_54_4=1; VULN_FLAGS="$VULN_FLAGS U_54_4"
else
    echo "  - 결과: [ 양호 ]"
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_54_1:$U_54_1, U_54_2:$U_54_2, U_54_3:$U_54_3, U_54_4:$U_54_4"

# 최종 판정
# 판단 기준: 암호화되지 않은 FTP 서비스가 비활성화된 경우 양호
if [[ $U_54_1 -eq 0 && $U_54_2 -eq 0 && $U_54_3 -eq 0 && $U_54_4 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
