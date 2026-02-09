#!/bin/bash

# 점검 내용 : FTP 서비스에 비인가자의 접근 가능 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_56_1=0  # [FTP - ftpusers] 파일 소유자 및 권한 설정
U_56_2=0  # [vsFTP - ftpusers] 파일 소유자 및 권한 설정
U_56_3=0  # [vsFTP-user_list] 파일 소유자 및 권한 설정
U_56_4=0  # [ProFTP - ftpusers] 파일 소유자 및 권한 설정
U_56_5=0  # [ProFTP - proftpd.conf] 파일 소유자 및 권한 설정

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-56] 점검 시작: FTP 서비스 접근 제어 설정"

# 1. [FTP - ftpusers] 점검
echo ""
echo "[1. FTP - ftpusers 점검]"
if [ -f "/etc/ftpusers" ]; then
    echo "▶ [FTP - ftpusers] 진입: 소유자 및 권한 확인"
    # 가이드 사례: 소유자 root, 권한 640 설정 확인
    OWNER=$(stat -c "%U" /etc/ftpusers)
    PERM=$(stat -c "%a" /etc/ftpusers)
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        echo "  - 결과: [ 취약 ] 소유자($OWNER) 또는 권한($PERM) 설정이 부적절합니다."
        U_56_1=1; VULN_FLAGS="$VULN_FLAGS U_56_1"
    else
        echo "  - 결과: [ 양호 ] 소유자 및 권한 설정이 적절합니다."
    fi
else
    echo "▶ [FTP - ftpusers] 진입: 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 2. [vsFTP - ftpusers] 점검
echo ""
echo "[2. vsFTP - ftpusers 점검]"
VS_FTPUSERS="/etc/vsftpd.ftpusers"
[ ! -f "$VS_FTPUSERS" ] && VS_FTPUSERS="/etc/vsftpd/ftpusers"

if [ -f "$VS_FTPUSERS" ]; then
    echo "▶ [vsFTP - ftpusers] 진입: 소유자 및 권한 확인"
    OWNER=$(stat -c "%U" "$VS_FTPUSERS")
    PERM=$(stat -c "%a" "$VS_FTPUSERS")
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        echo "  - 결과: [ 취약 ] 소유자($OWNER) 또는 권한($PERM) 설정이 부적절합니다."
        U_56_2=1; VULN_FLAGS="$VULN_FLAGS U_56_2"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [vsFTP - ftpusers] 진입: 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 3. [vsFTP-user_list] 점검
echo ""
echo "[3. vsFTP-user_list 점검]"
VS_USERLIST="/etc/vsftpd.user_list"
[ ! -f "$VS_USERLIST" ] && VS_USERLIST="/etc/vsftpd/user_list"

if [ -f "$VS_USERLIST" ]; then
    echo "▶ [vsFTP-user_list] 진입: 소유자 및 권한 확인"
    OWNER=$(stat -c "%U" "$VS_USERLIST")
    PERM=$(stat -c "%a" "$VS_USERLIST")
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        echo "  - 결과: [ 취약 ] 소유자($OWNER) 또는 권한($PERM) 설정이 부적절합니다."
        U_56_3=1; VULN_FLAGS="$VULN_FLAGS U_56_3"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [vsFTP-user_list] 진입: 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 4. [ProFTP - ftpusers] 점검
echo ""
echo "[4. ProFTP - ftpusers 점검]"
if [ -f "/etc/ftpd/ftpusers" ]; then
    echo "▶ [ProFTP - ftpusers] 진입: 소유자 및 권한 확인"
    OWNER=$(stat -c "%U" /etc/ftpd/ftpusers)
    PERM=$(stat -c "%a" /etc/ftpd/ftpusers)
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        echo "  - 결과: [ 취약 ] 소유자($OWNER) 또는 권한($PERM) 설정이 부적절합니다."
        U_56_4=1; VULN_FLAGS="$VULN_FLAGS U_56_4"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [ProFTP - ftpusers] 진입: 파일이 존재하지 않습니다. [ 양호 ]"
fi

# 5. [ProFTP - proftpd.conf] 점검
echo ""
echo "[5. ProFTP - proftpd.conf 점검]"
PROFTP_CONF="/etc/proftpd/proftpd.conf"
[ ! -f "$PROFTP_CONF" ] && PROFTP_CONF="/etc/proftpd.conf"

if [ -f "$PROFTP_CONF" ]; then
    echo "▶ [ProFTP - proftpd.conf] 진입: 소유자 및 권한 확인"
    OWNER=$(stat -c "%U" "$PROFTP_CONF")
    PERM=$(stat -c "%a" "$PROFTP_CONF")
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        echo "  - 결과: [ 취약 ] 소유자($OWNER) 또는 권한($PERM) 설정이 부적절합니다."
        U_56_5=1; VULN_FLAGS="$VULN_FLAGS U_56_5"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [ProFTP - proftpd.conf] 진입: 설정 파일이 존재하지 않습니다. [ 양호 ]"
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_56_1:$U_56_1, U_56_2:$U_56_2, U_56_3:$U_56_3, U_56_4:$U_56_4, U_56_5:$U_56_5"

# 최종 판정
# 판단 기준: 특정 IP/호스트 접근 제어 설정 적용 및 설정 파일 권한이 적절한 경우 양호
if [[ $U_56_1 -eq 0 && $U_56_2 -eq 0 && $U_56_3 -eq 0 && $U_56_4 -eq 0 && $U_56_5 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
