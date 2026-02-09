#!/bin/bash

# [U-62] 로그인 시 경고 메시지 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.150-158 [cite: 1724-1948]
# 점검 목적 : 서버 및 서비스 접속 시 경고 메시지를 출력하여 비인가자의 책임 소재를 명확히 함
# 자동 조치 가능 유무 : 불가능 (정책에 맞는 경고 문구 작성 및 파일 생성 필요)
# 플래그 설명:
#   U_62_1 : [Server] /etc/motd, /etc/issue 파일 내용 없음
#   U_62_2 : [Telnet] /etc/issue.net 파일 내용 없음 (Telnet 사용 시)
#   U_62_3 : [SSH] sshd_config 내 Banner 설정 미흡
#   U_62_4 : [Sendmail] SmtpGreetingMessage 설정 미흡
#   U_62_5 : [Postfix] smtpd_banner 설정 미흡
#   U_62_6 : [vsFTP] ftpd_banner 설정 미흡
#   U_62_7 : [ProFTP] DisplayLogin 설정 미흡
#   U_62_8 : [DNS] named.conf 내 version 설정 미흡

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-62] 로그인 시 경고 메시지 설정 점검 시작"
echo "----------------------------------------------------------------"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[오류]${NC} Root 권한으로 실행해 주십시오."
    exit 1
fi

VULN_STATUS=0
VULN_FLAGS=()

# ----------------------------------------------------------------
# 1. [Server] 기본 배너 점검 (U_62_1)
# ----------------------------------------------------------------
# /etc/motd와 /etc/issue 파일에 내용이 있는지 확인
if [[ -s "/etc/motd" ]] || [[ -s "/etc/issue" ]]; then
    echo -e "${GREEN}[양호]${NC} [Server] 기본 서버 배너(motd/issue)가 설정되어 있습니다."
else
    VULN_STATUS=1
    VULN_FLAGS+=("U_62_1")
    echo -e "${RED}[취약]${NC} [Server] /etc/motd 또는 /etc/issue 파일에 경고 메시지가 없습니다."
fi

# ----------------------------------------------------------------
# 2. [Telnet] 배너 점검 (U_62_2)
# ----------------------------------------------------------------
# Telnet 패키지가 있을 경우에만 점검
PKG_TELNET=$(rpm -qa | grep "telnet-server")
if [[ -n "$PKG_TELNET" ]]; then
    if [[ -s "/etc/issue.net" ]]; then
        echo -e "${GREEN}[양호]${NC} [Telnet] /etc/issue.net 파일에 경고 메시지가 설정되어 있습니다."
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_62_2")
        echo -e "${RED}[취약]${NC} [Telnet] Telnet 패키지가 설치되어 있으나 /etc/issue.net 파일이 비어있습니다."
    fi
fi

# ----------------------------------------------------------------
# 3. [SSH] 배너 점검 (U_62_3)
# ----------------------------------------------------------------
# Rocky Linux는 openssh-server가 기본
SSHD_CONF="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONF" ]]; then
    BANNER_CHECK=$(grep "^Banner" "$SSHD_CONF")
    if [[ -n "$BANNER_CHECK" ]]; then
        echo -e "${GREEN}[양호]${NC} [SSH] Banner 설정이 확인되었습니다."
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_62_3")
        echo -e "${RED}[취약]${NC} [SSH] sshd_config 파일에 Banner 설정이 없습니다."
    fi
fi

# ----------------------------------------------------------------
# 4. [Sendmail] 배너 점검 (U_62_4)
# ----------------------------------------------------------------
PKG_SENDMAIL=$(rpm -qa | grep -E "^sendmail-[0-9]")
if [[ -n "$PKG_SENDMAIL" ]]; then
    SENDMAIL_CF="/etc/mail/sendmail.cf"
    if [[ -f "$SENDMAIL_CF" ]]; then
        GREET_MSG=$(grep "SmtpGreetingMessage" "$SENDMAIL_CF" | grep -v "^#")
        if [[ -n "$GREET_MSG" ]]; then
            echo -e "${GREEN}[양호]${NC} [Sendmail] SmtpGreetingMessage 설정 확인됨."
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_62_4")
            echo -e "${RED}[취약]${NC} [Sendmail] SmtpGreetingMessage 설정이 없습니다."
        fi
    fi
fi

# ----------------------------------------------------------------
# 5. [Postfix] 배너 점검 (U_62_5)
# ----------------------------------------------------------------
PKG_POSTFIX=$(rpm -qa | grep -E "^postfix-[0-9]")
if [[ -n "$PKG_POSTFIX" ]]; then
    POSTFIX_CONF="/etc/postfix/main.cf"
    if [[ -f "$POSTFIX_CONF" ]]; then
        SMTP_BANNER=$(grep "^smtpd_banner" "$POSTFIX_CONF")
        if [[ -n "$SMTP_BANNER" ]]; then
            echo -e "${GREEN}[양호]${NC} [Postfix] smtpd_banner 설정 확인됨."
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_62_5")
            echo -e "${RED}[취약]${NC} [Postfix] smtpd_banner 설정이 없습니다."
        fi
    fi
fi

# ----------------------------------------------------------------
# 6. [vsFTP] 배너 점검 (U_62_6)
# ----------------------------------------------------------------
PKG_VSFTP=$(rpm -qa | grep "vsftpd")
if [[ -n "$PKG_VSFTP" ]]; then
    VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
    if [[ ! -f "$VSFTP_CONF" ]]; then VSFTP_CONF="/etc/vsftpd.conf"; fi
    
    if [[ -f "$VSFTP_CONF" ]]; then
        FTP_BANNER=$(grep "^ftpd_banner" "$VSFTP_CONF")
        if [[ -n "$FTP_BANNER" ]]; then
            echo -e "${GREEN}[양호]${NC} [vsFTP] ftpd_banner 설정 확인됨."
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_62_6")
            echo -e "${RED}[취약]${NC} [vsFTP] ftpd_banner 설정이 없습니다."
        fi
    fi
fi

# ----------------------------------------------------------------
# 7. [ProFTP] 배너 점검 (U_62_7)
# ----------------------------------------------------------------
PKG_PROFTP=$(rpm -qa | grep "proftpd")
if [[ -n "$PKG_PROFTP" ]]; then
    PROFTP_CONF="/etc/proftpd.conf"
    if [[ ! -f "$PROFTP_CONF" ]]; then PROFTP_CONF="/etc/proftpd/proftpd.conf"; fi
    
    if [[ -f "$PROFTP_CONF" ]]; then
        DISPLAY_LOGIN=$(grep "DisplayLogin" "$PROFTP_CONF" | grep -v "^#")
        if [[ -n "$DISPLAY_LOGIN" ]]; then
            echo -e "${GREEN}[양호]${NC} [ProFTP] DisplayLogin 설정 확인됨."
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_62_7")
            echo -e "${RED}[취약]${NC} [ProFTP] DisplayLogin 설정이 없습니다."
        fi
    fi
fi

# ----------------------------------------------------------------
# 8. [DNS] 배너 점검 (U_62_8)
# ----------------------------------------------------------------
PKG_BIND=$(rpm -qa | grep -E "^bind-[0-9]")
if [[ -n "$PKG_BIND" ]]; then
    NAMED_CONF="/etc/named.conf"
    if [[ -f "$NAMED_CONF" ]]; then
        VERSION_CHECK=$(grep "version" "$NAMED_CONF" | grep -v "^#")
        if [[ -n "$VERSION_CHECK" ]]; then
            echo -e "${GREEN}[양호]${NC} [DNS] version 설정(정보 은폐)이 확인되었습니다."
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_62_8")
            echo -e "${RED}[취약]${NC} [DNS] named.conf에 version 설정이 없습니다."
        fi
    fi
fi

# ----------------------------------------------------------------
# 최종 결과 출력
# ----------------------------------------------------------------
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (설치된 서비스의 로그인 경고 메시지 설정 적절)"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
