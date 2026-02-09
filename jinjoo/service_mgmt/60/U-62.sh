#!/bin/bash

# 점검 내용 : 로그인 시 불필요한 정보 차단 및 경고 메시지 출력 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_62_1=0 # [서버] /etc/motd, /etc/issue
U_62_2=0 # [Telnet] /etc/issue.net
U_62_3=0 # [SSH] Banner 설정
U_62_4=0 # [Sendmail] SmtpGreetingMessage
U_62_5=0 # [Postfix] smtpd_banner
U_62_6=0 # [Exim] smtp_banner
U_62_7=0 # [vsFTP] ftpd_banner
U_62_8=0 # [ProFTP] DisplayLogin
U_62_9=0 # [DNS] version 설정

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-62] 점검 시작: 로그인 시 경고 메시지 제공"

# 1. [서버] 점검
echo ""
echo "[1. 서버 배너 점검]"
if [ -s "/etc/motd" ] || [ -s "/etc/issue" ]; then
    echo "  - 결과: [ 양호 ] /etc/motd 또는 /etc/issue에 메시지가 존재합니다."
else
    echo "  - 결과: [ 취약 ] 로컬 로그인 경고 메시지가 설정되지 않았습니다."
    U_62_1=1; VULN_FLAGS="$VULN_FLAGS U_62_1"
fi

# 2. [Telnet] 점검
echo ""
echo "[2. Telnet 배너 점검]"
if systemctl is-active --quiet telnet.socket 2>/dev/null; then
    if [ -s "/etc/issue.net" ]; then
        echo "  - 결과: [ 양호 ] /etc/issue.net에 메시지가 존재합니다."
    else
        echo "  - 결과: [ 취약 ] Telnet 경고 메시지가 설정되지 않았습니다."
        U_62_2=1; VULN_FLAGS="$VULN_FLAGS U_62_2"
    fi
else
    echo "  - 결과: [ 양호 ] Telnet 서비스를 사용하지 않습니다."
fi

# 3. [SSH] 점검
echo ""
echo "[3. SSH 배너 점검]"
SSH_CONF="/etc/ssh/sshd_config"
if [ -f "$SSH_CONF" ]; then
    BANNER_PATH=$(grep -i "^Banner" "$SSH_CONF" | awk '{print $2}')
    if [ -n "$BANNER_PATH" ] && [ -s "$BANNER_PATH" ]; then
        echo "  - 결과: [ 양호 ] SSH Banner 설정이 활성화되어 있습니다. ($BANNER_PATH)"
    else
        echo "  - 결과: [ 취약 ] SSH Banner 설정이 누락되었거나 파일이 비어 있습니다."
        U_62_3=1; VULN_FLAGS="$VULN_FLAGS U_62_3"
    fi
else
    echo "  - 결과: [ 양호 ] SSH 설정 파일을 찾을 수 없습니다."
fi

# 4. [Sendmail] 점검
echo ""
echo "[4. Sendmail 배너 점검]"
if [ -f "/etc/mail/sendmail.cf" ]; then
    if grep -qi "SmtpGreetingMessage" /etc/mail/sendmail.cf; then
        echo "  - 결과: [ 양호 ] SmtpGreetingMessage 설정이 존재합니다."
    else
        echo "  - 결과: [ 취약 ] Sendmail 배너 설정이 미비합니다."
        U_62_4=1; VULN_FLAGS="$VULN_FLAGS U_62_4"
    fi
else
    echo "  - 결과: [ 양호 ] Sendmail 서비스를 사용하지 않습니다."
fi

# 5. [Postfix] 점검
echo ""
echo "[5. Postfix 배너 점검]"
if [ -f "/etc/postfix/main.cf" ]; then
    if grep -qi "^smtpd_banner" /etc/postfix/main.cf; then
        echo "  - 결과: [ 양호 ] smtpd_banner 설정이 존재합니다."
    else
        echo "  - 결과: [ 취약 ] Postfix 배너 설정이 미비합니다."
        U_62_5=1; VULN_FLAGS="$VULN_FLAGS U_62_5"
    fi
else
    echo "  - 결과: [ 양호 ] Postfix 서비스를 사용하지 않습니다."
fi

# 6. [Exim] 점검
echo ""
echo "[6. Exim 배너 점검]"
EXIM_CONF="/etc/exim/exim.conf"
[ ! -f "$EXIM_CONF" ] && EXIM_CONF="/etc/exim4/exim4.conf"
if [ -f "$EXIM_CONF" ]; then
    if grep -qi "^smtp_banner" "$EXIM_CONF"; then
        echo "  - 결과: [ 양호 ] smtp_banner 설정이 존재합니다."
    else
        echo "  - 결과: [ 취약 ] Exim 배너 설정이 미비합니다."
        U_62_6=1; VULN_FLAGS="$VULN_FLAGS U_62_6"
    fi
else
    echo "  - 결과: [ 양호 ] Exim 서비스를 사용하지 않습니다."
fi

# 7. [vsFTP] 점검
echo ""
echo "[7. vsFTP 배너 점검]"
VS_CONF="/etc/vsftpd.conf"
[ ! -f "$VS_CONF" ] && VS_CONF="/etc/vsftpd/vsftpd.conf"
if [ -f "$VS_CONF" ]; then
    if grep -qi "^ftpd_banner" "$VS_CONF"; then
        echo "  - 결과: [ 양호 ] ftpd_banner 설정이 존재합니다."
    else
        echo "  - 결과: [ 취약 ] vsFTP 배너 설정이 미비합니다."
        U_62_7=1; VULN_FLAGS="$VULN_FLAGS U_62_7"
    fi
else
    echo "  - 결과: [ 양호 ] vsFTP 서비스를 사용하지 않습니다."
fi

# 8. [ProFTP] 점검
echo ""
echo "[8. ProFTP 배너 점검]"
PRO_CONF="/etc/proftpd/proftpd.conf"
[ ! -f "$PRO_CONF" ] && PRO_CONF="/etc/proftpd.conf"
if [ -f "$PRO_CONF" ]; then
    if grep -qi "DisplayLogin" "$PRO_CONF"; then
        echo "  - 결과: [ 양호 ] DisplayLogin 설정이 존재합니다."
    else
        echo "  - 결과: [ 취약 ] ProFTP 배너 설정이 미비합니다."
        U_62_8=1; VULN_FLAGS="$VULN_FLAGS U_62_8"
    fi
else
    echo "  - 결과: [ 양호 ] ProFTP 서비스를 사용하지 않습니다."
fi

# 9. [DNS] 점검
echo ""
echo "[9. DNS 배너 점검]"
BIND_CONF="/etc/bind/named.conf.options"
[ ! -f "$BIND_CONF" ] && BIND_CONF="/etc/bind/named.conf"
if [ -f "$BIND_CONF" ]; then
    if grep -qi "version" "$BIND_CONF"; then
        echo "  - 결과: [ 양호 ] version 설정(보안 배너)이 존재합니다."
    else
        echo "  - 결과: [ 취약 ] DNS 버전 숨김/배너 설정이 미비합니다."
        U_62_9=1; VULN_FLAGS="$VULN_FLAGS U_62_9"
    fi
else
    echo "  - 결과: [ 양호 ] DNS 서비스를 사용하지 않습니다."
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_62_1:$U_62_1, U_62_2:$U_62_2, U_62_3:$U_62_3, U_62_4:$U_62_4, U_62_5:$U_62_5, U_62_6:$U_62_6, U_62_7:$U_62_7, U_62_8:$U_62_8, U_62_9:$U_62_9"

# 최종 판정
if [[ $U_62_1 -eq 0 && $U_62_2 -eq 0 && $U_62_3 -eq 0 && $U_62_4 -eq 0 && $U_62_5 -eq 0 && $U_62_6 -eq 0 && $U_62_7 -eq 0 && $U_62_8 -eq 0 && $U_62_9 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
