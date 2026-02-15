#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 로그인 시 불필요한 정보 차단 및 경고 메시지 출력 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
U_62_1=0 # [서버] /etc/motd, /etc/issue
U_62_2=0 # [Telnet] /etc/issue.net
U_62_3=0 # [SSH] Banner 설정
U_62_4=0 # [Sendmail] SmtpGreetingMessage
U_62_5=0 # [Postfix] smtpd_banner
U_62_6=0 # [Exim] smtp_banner
U_62_7=0 # [vsFTP] ftpd_banner
U_62_8=0 # [ProFTP] DisplayLogin
U_62_9=0 # [DNS] version 설정

# --- 3. 점검 로직 수행 ---

# 1. [서버] 점검
# /etc/motd 또는 /etc/issue 파일에 내용이 있으면 양호
if [ -s "/etc/motd" ] || [ -s "/etc/issue" ]; then
    U_62_1=0
else
    U_62_1=1
fi

# 2. [Telnet] 점검
# Telnet 서비스가 활성화된 경우에만 점검
if systemctl is-active --quiet telnet.socket 2>/dev/null; then
    if [ ! -s "/etc/issue.net" ]; then
        U_62_2=1
    fi
else
    U_62_2=0
fi

# 3. [SSH] 점검
SSH_CONF="/etc/ssh/sshd_config"
if [ -f "$SSH_CONF" ]; then
    BANNER_PATH=$(grep -i "^Banner" "$SSH_CONF" | awk '{print $2}')
    # Banner 설정이 있고, 해당 파일이 비어있지 않아야 양호
    if [ -n "$BANNER_PATH" ] && [ -s "$BANNER_PATH" ]; then
        U_62_3=0
    else
        U_62_3=1
    fi
else
    U_62_3=0
fi

# 4. [Sendmail] 점검
if [ -f "/etc/mail/sendmail.cf" ]; then
    if ! grep -qi "SmtpGreetingMessage" /etc/mail/sendmail.cf; then
        U_62_4=1
    fi
else
    U_62_4=0
fi

# 5. [Postfix] 점검
if [ -f "/etc/postfix/main.cf" ]; then
    if ! grep -qi "^smtpd_banner" /etc/postfix/main.cf; then
        U_62_5=1
    fi
else
    U_62_5=0
fi

# 6. [Exim] 점검
EXIM_CONF="/etc/exim/exim.conf"
[ ! -f "$EXIM_CONF" ] && EXIM_CONF="/etc/exim4/exim4.conf"
if [ -f "$EXIM_CONF" ]; then
    if ! grep -qi "^smtp_banner" "$EXIM_CONF"; then
        U_62_6=1
    fi
else
    U_62_6=0
fi

# 7. [vsFTP] 점검
VS_CONF="/etc/vsftpd.conf"
[ ! -f "$VS_CONF" ] && VS_CONF="/etc/vsftpd/vsftpd.conf"
if [ -f "$VS_CONF" ]; then
    if ! grep -qi "^ftpd_banner" "$VS_CONF"; then
        U_62_7=1
    fi
else
    U_62_7=0
fi

# 8. [ProFTP] 점검
PRO_CONF="/etc/proftpd/proftpd.conf"
[ ! -f "$PRO_CONF" ] && PRO_CONF="/etc/proftpd.conf"
if [ -f "$PRO_CONF" ]; then
    if ! grep -qi "DisplayLogin" "$PRO_CONF"; then
        U_62_8=1
    fi
else
    U_62_8=0
fi

# 9. [DNS] 점검
BIND_CONF="/etc/bind/named.conf.options"
[ ! -f "$BIND_CONF" ] && BIND_CONF="/etc/bind/named.conf"
if [ -f "$BIND_CONF" ]; then
    if ! grep -qi "version" "$BIND_CONF"; then
        U_62_9=1
    fi
else
    U_62_9=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [[ $U_62_1 -eq 0 && $U_62_2 -eq 0 && $U_62_3 -eq 0 && $U_62_4 -eq 0 && $U_62_5 -eq 0 && $U_62_6 -eq 0 && $U_62_7 -eq 0 && $U_62_8 -eq 0 && $U_62_9 -eq 0 ]]; then
    IS_VUL=0
else
    IS_VUL=1
fi

# --- 5. JSON 출력 (Stdout) ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP_ADDR",
    "user": "$CURRENT_USER"
  },
  "result": {
    "flag_id": "U-62",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_62_1": $U_62_1,
      "U_62_2": $U_62_2,
      "U_62_3": $U_62_3,
      "U_62_4": $U_62_4,
      "U_62_5": $U_62_5,
      "U_62_6": $U_62_6,
      "U_62_7": $U_62_7,
      "U_62_8": $U_62_8,
      "U_62_9": $U_62_9
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
