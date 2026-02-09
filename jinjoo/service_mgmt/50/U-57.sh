#!/bin/bash

# 점검 내용 : FTP 서비스에 root 계정 접근 제한 설정 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_57_1=0  # [기본 FTP-ftpusers] root 계정 접근 제한 설정 여부
U_57_2=0  # [vsFTP - ftpusers] root 계정 접근 제한 설정 여부
U_57_3=0  # [vsFTP-user_list] root 계정 접근 제한 설정 여부
U_57_4=0  # [ProFTP - ftpusers] root 계정 접근 제한 설정 여부
U_57_5=0  # [ProFTP - proftpd.conf] RootLogin off 설정 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-57] 점검 시작: Ftpusers 파일 설정"

# 1. [기본 FTP-ftpusers] 점검
echo ""
echo "[1. 기본 FTP-ftpusers 점검]"
# 가이드 사례: /etc/ftpusers 내 root 존재 여부 확인
FTPUSERS_FILE="/etc/ftpusers"
[ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/ftpd/ftpusers"

if [ -f "$FTPUSERS_FILE" ]; then
    echo "▶ [기본 FTP] 진입: $FTPUSERS_FILE 내 root 제한 확인"
    if ! grep -qx "root" "$FTPUSERS_FILE"; then
        echo "  - 결과: [ 취약 ] root 계정 접속 제한 설정이 누락되었습니다."
        U_57_1=1; VULN_FLAGS="$VULN_FLAGS U_57_1"
    else
        echo "  - 결과: [ 양호 ] root 계정 접속이 차단되어 있습니다."
    fi
else
    echo "▶ [기본 FTP] 진입: 파일 미존재로 [ 양호 ] 처리합니다."
fi

# 2. [vsFTP - ftpusers] 점검
echo ""
echo "[2. vsFTP - ftpusers 점검]"
# 가이드 사례: userlist_enable=NO 일 때 ftpusers 파일 확인
VS_FTPUSERS="/etc/vsftpd.ftpusers"
[ ! -f "$VS_FTPUSERS" ] && VS_FTPUSERS="/etc/vsftpd/ftpusers"

if [ -f "$VS_FTPUSERS" ]; then
    echo "▶ [vsFTP - ftpusers] 진입: root 제한 확인"
    if ! grep -qx "root" "$VS_FTPUSERS"; then
        echo "  - 결과: [ 취약 ] root 계정 접속 제한 설정이 누락되었습니다."
        U_57_2=1; VULN_FLAGS="$VULN_FLAGS U_57_2"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [vsFTP - ftpusers] 진입: 파일 미존재로 [ 양호 ] 처리합니다."
fi

# 3. [vsFTP-user_list] 점검
echo ""
echo "[3. vsFTP-user_list 점검]"
# 가이드 사례: userlist_enable=YES 및 user_list_deny=YES 일 때 root 확인
VS_USERLIST="/etc/vsftpd.user_list"
[ ! -f "$VS_USERLIST" ] && VS_USERLIST="/etc/vsftpd/user_list"

if [ -f "$VS_USERLIST" ]; then
    echo "▶ [vsFTP-user_list] 진입: root 제한 확인"
    if ! grep -qx "root" "$VS_USERLIST"; then
        echo "  - 결과: [ 취약 ] user_list 내 root 계정 차단 설정이 누락되었습니다."
        U_57_3=1; VULN_FLAGS="$VULN_FLAGS U_57_3"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [vsFTP-user_list] 진입: 파일 미존재로 [ 양호 ] 처리합니다."
fi

# 4. [ProFTP - ftpusers] 점검
echo ""
echo "[4. ProFTP - ftpusers 점검]"
# 가이드 사례: UseFtpUsers on 일 때 ftpusers 확인
if [ -f "/etc/ftpd/ftpusers" ]; then
    echo "▶ [ProFTP - ftpusers] 진입: root 제한 확인"
    if ! grep -qx "root" "/etc/ftpd/ftpusers"; then
        echo "  - 결과: [ 취약 ] root 계정 접속 제한 설정이 누락되었습니다."
        U_57_4=1; VULN_FLAGS="$VULN_FLAGS U_57_4"
    else
        echo "  - 결과: [ 양호 ]"
    fi
else
    echo "▶ [ProFTP - ftpusers] 진입: 파일 미존재로 [ 양호 ] 처리합니다."
fi

# 5. [ProFTP - proftpd.conf] 점검
echo ""
echo "[5. ProFTP - proftpd.conf 점검]"
# 가이드 사례: UseFtpUsers off 일 때 RootLogin off 설정 확인
PROFTP_CONF="/etc/proftpd/proftpd.conf"
[ ! -f "$PROFTP_CONF" ] && PROFTP_CONF="/etc/proftpd.conf"

if [ -f "$PROFTP_CONF" ]; then
    echo "▶ [ProFTP - proftpd.conf] 진입: RootLogin 설정 확인"
    ROOT_LOGIN_OFF=$(grep -i "RootLogin" "$PROFTP_CONF" | grep -i "off" | grep -v "^#")
    if [ -z "$ROOT_LOGIN_OFF" ]; then
        echo "  - 결과: [ 취약 ] RootLogin off 설정이 누락되어 있습니다."
        U_57_5=1; VULN_FLAGS="$VULN_FLAGS U_57_5"
    else
        echo "  - 결과: [ 양호 ] RootLogin off 설정이 확인되었습니다."
    fi
else
    echo "▶ [ProFTP - proftpd.conf] 진입: 설정 파일 미존재로 [ 양호 ] 처리합니다."
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_57_1:$U_57_1, U_57_2:$U_57_2, U_57_3:$U_57_3, U_57_4:$U_57_4, U_57_5:$U_57_5"

# 최종 판정
# 판단 기준: root 계정 접속을 차단한 경우 양호 
if [[ $U_57_1 -eq 0 && $U_57_2 -eq 0 && $U_57_3 -eq 0 && $U_57_4 -eq 0 && $U_57_5 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
