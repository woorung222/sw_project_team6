#!/bin/bash

# 점검 내용 : FTP 서비스 접속 배너를 통한 불필요한 정보 노출 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_53_1=0  # [vsFTP] ftpd_banner 설정 및 정보 노출 여부
U_53_2=0  # [ProFTP] ServerIdent 설정 및 정보 노출 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-53] 점검 시작: FTP 서비스 정보 노출 제한"

# 1. [vsFTP] 점검
echo ""
echo "[1. vsFTP 점검]"
# 가이드 사례: vsftpd.conf 파일 내 ftpd_banner 설정 확인
VSFTP_CONF="/etc/vsftpd.conf"
[ ! -f "$VSFTP_CONF" ] && VSFTP_CONF="/etc/vsftpd/vsftpd.conf"

if [ -f "$VSFTP_CONF" ]; then
    echo "▶ [vsFTP] 진입: $VSFTP_CONF 설정 확인"
    BANNER_CHECK=$(grep -i "ftpd_banner" "$VSFTP_CONF" | grep -v "^#")
    
    if [ -z "$BANNER_CHECK" ]; then
        echo "  - 결과: [ 취약 ] ftpd_banner 설정이 누락되어 기본 배너(버전 정보 등)가 노출될 수 있습니다."
        U_53_1=1; VULN_FLAGS="$VULN_FLAGS U_53_1"
    else
        echo "  - 결과: [ 양호 ] 배너 설정이 존재합니다."
        echo "  - 설정 내용: $BANNER_CHECK"
    fi
else
    echo "▶ [vsFTP] 진입: 설정 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 2. [ProFTP] 점검
echo ""
echo "[2. ProFTP 점검]"
# 가이드 사례: proftpd.conf 파일 내 ServerIdent 설정 확인
PROFTP_CONF="/etc/proftpd.conf"
[ ! -f "$PROFTP_CONF" ] && PROFTP_CONF="/etc/proftpd/proftpd.conf"

if [ -f "$PROFTP_CONF" ]; then
    echo "▶ [ProFTP] 진입: $PROFTP_CONF 설정 확인"
    IDENT_CHECK=$(grep -i "ServerIdent" "$PROFTP_CONF" | grep -v "^#")
    
    # 가이드 기준: ServerIdent off 또는 특정 메시지 설정 시 양호
    if [ -z "$IDENT_CHECK" ] || [[ "$IDENT_CHECK" == *"on"* && "$IDENT_CHECK" != *' "'* ]]; then
        echo "  - 결과: [ 취약 ] ServerIdent 설정이 off가 아니거나 정보 제한이 설정되지 않았습니다."
        U_53_2=1; VULN_FLAGS="$VULN_FLAGS U_53_2"
    else
        echo "  - 결과: [ 양호 ] ServerIdent 설정이 적절합니다."
        echo "  - 설정 내용: $IDENT_CHECK"
    fi
else
    echo "▶ [ProFTP] 진입: 설정 파일이 존재하지 않습니다. [ 양호 ]"
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_53_1:$U_53_1, U_53_2:$U_53_2"

# 최종 판정
# 판단 기준: FTP 접속 배너에 노출되는 정보가 없는 경우 양호
if [[ $U_53_1 -eq 0 && $U_53_2 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
