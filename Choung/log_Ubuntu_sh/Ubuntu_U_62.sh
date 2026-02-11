#!/bin/bash

# [U-62] 로그인 시 불필요한 정보 차단 및 경고 메시지 출력 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-62"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then
    source "$BASE_DIR/common_logging.sh"
else
    echo "Warning: common_logging.sh not found." >&2
    run_cmd() { eval "$2"; }
    log_step() { :; }
    log_basis() { :; }
fi

# 2. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기화
U_62_1=0; U_62_2=0; U_62_3=0; U_62_4=0; U_62_5=0; U_62_6=0; U_62_7=0; U_62_8=0; U_62_9=0
IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_62_1] 서버 배너 (/etc/motd, /etc/issue) 점검
# 파일 내용이 있는지 확인 (ls -l로 크기 확인 및 cat으로 내용 일부 확인)
CHECK_FILES=$(run_cmd "[U_62_1] 배너 파일 확인" "ls -l /etc/motd /etc/issue 2>/dev/null || echo 'none'")

if [[ "$CHECK_FILES" != "none" ]]; then
    # 내용 확인 (비어있지 않은지 grep으로 체크)
    CONTENT_CHECK=$(run_cmd "[U_62_1] 배너 파일 내용 유무 확인" "grep -r . /etc/motd /etc/issue 2>/dev/null || echo 'empty'")
    
    if [[ "$CONTENT_CHECK" != "empty" ]]; then
        U_62_1=0
        log_basis "[U_62_1] /etc/motd 또는 /etc/issue 파일에 내용이 존재함" "양호"
    else
        U_62_1=1
        log_basis "[U_62_1] 배너 파일이 존재하나 내용이 비어있음" "취약"
    fi
else
    U_62_1=1
    log_basis "[U_62_1] /etc/motd 및 /etc/issue 파일이 존재하지 않음" "취약"
fi

# 2. [U_62_2] Telnet 배너 (/etc/issue.net) 점검
# Telnet 서비스 활성화 여부 확인
TELNET_ACTIVE=$(run_cmd "[U_62_2] Telnet 서비스 상태" "systemctl is-active telnet.socket 2>/dev/null || echo 'inactive'")

if [[ "$TELNET_ACTIVE" == "active" ]]; then
    # Telnet 사용 시 issue.net 점검
    ISSUE_NET_CHECK=$(run_cmd "[U_62_2] issue.net 파일 확인" "ls -l /etc/issue.net 2>/dev/null || echo 'none'")
    
    if [[ "$ISSUE_NET_CHECK" != "none" ]]; then
        CONTENT_NET=$(run_cmd "[U_62_2] issue.net 내용 확인" "cat /etc/issue.net 2>/dev/null || echo ''")
        if [[ -n "$CONTENT_NET" ]]; then
            log_basis "[U_62_2] Telnet 배너(issue.net) 설정됨" "양호"
        else
            U_62_2=1
            log_basis "[U_62_2] Telnet 사용 중이나 issue.net 내용이 비어있음" "취약"
        fi
    else
        U_62_2=1
        log_basis "[U_62_2] Telnet 사용 중이나 /etc/issue.net 파일 없음" "취약"
    fi
else
    U_62_2=0
    log_basis "[U_62_2] Telnet 서비스를 사용하지 않음" "양호"
fi

# 3. [U_62_3] SSH Banner 점검
SSH_CONF="/etc/ssh/sshd_config"
if [[ -f "$SSH_CONF" ]]; then
    BANNER_LINE=$(run_cmd "[U_62_3] SSH Banner 설정 검색" "grep -i '^Banner' \"$SSH_CONF\" || echo 'none'")
    
    if [[ "$BANNER_LINE" != "none" ]]; then
        BANNER_PATH=$(echo "$BANNER_LINE" | awk '{print $2}')
        # 지정된 파일이 실제로 있고 내용이 있는지 확인
        FILE_CHECK=$(run_cmd "[U_62_3] 지정된 Banner 파일 확인" "ls -l \"$BANNER_PATH\" 2>/dev/null || echo 'none'")
        
        if [[ "$FILE_CHECK" != "none" ]]; then
            U_62_3=0
            log_basis "[U_62_3] SSH Banner 설정 및 파일 확인됨: $BANNER_LINE" "양호"
        else
            U_62_3=1
            log_basis "[U_62_3] SSH Banner 설정은 있으나 지정된 파일($BANNER_PATH)이 없음" "취약"
        fi
    else
        U_62_3=1
        log_basis "[U_62_3] SSH Banner 설정이 sshd_config에 없음" "취약"
    fi
else
    U_62_3=0
    TMP=$(run_cmd "[U_62_3] SSH 설정 파일 확인" "ls /etc/ssh/sshd_config 2>/dev/null || echo '미존재'")
    log_basis "[U_62_3] SSH 설정 파일 없음" "양호"
fi

# 4. [U_62_4] Sendmail 점검
if [[ -f "/etc/mail/sendmail.cf" ]]; then
    SMTP_GREET=$(run_cmd "[U_62_4] Sendmail Greeting 확인" "grep -i 'SmtpGreetingMessage' /etc/mail/sendmail.cf || echo 'none'")
    if [[ "$SMTP_GREET" == "none" ]]; then
        U_62_4=1
        log_basis "[U_62_4] Sendmail SmtpGreetingMessage 설정 미발견" "취약"
    else
        log_basis "[U_62_4] Sendmail SmtpGreetingMessage 설정됨: $SMTP_GREET" "양호"
    fi
else
    U_62_4=0
    TMP=$(run_cmd "[U_62_4] Sendmail 파일 확인" "ls /etc/mail/sendmail.cf 2>/dev/null || echo '미존재'")
    log_basis "[U_62_4] Sendmail 설정 파일 없음" "양호"
fi

# 5. [U_62_5] Postfix 점검
if [[ -f "/etc/postfix/main.cf" ]]; then
    POSTFIX_BANNER=$(run_cmd "[U_62_5] Postfix Banner 확인" "grep -i '^smtpd_banner' /etc/postfix/main.cf || echo 'none'")
    if [[ "$POSTFIX_BANNER" == "none" ]]; then
        U_62_5=1
        log_basis "[U_62_5] Postfix smtpd_banner 설정 미발견" "취약"
    else
        log_basis "[U_62_5] Postfix smtpd_banner 설정됨: $POSTFIX_BANNER" "양호"
    fi
else
    U_62_5=0
    TMP=$(run_cmd "[U_62_5] Postfix 파일 확인" "ls /etc/postfix/main.cf 2>/dev/null || echo '미존재'")
    log_basis "[U_62_5] Postfix 설정 파일 없음" "양호"
fi

# 6. [U_62_6] Exim 점검
EXIM_CONF=""
if [[ -f "/etc/exim/exim.conf" ]]; then EXIM_CONF="/etc/exim/exim.conf";
elif [[ -f "/etc/exim4/exim4.conf" ]]; then EXIM_CONF="/etc/exim4/exim4.conf"; fi

if [[ -n "$EXIM_CONF" ]]; then
    EXIM_BANNER=$(run_cmd "[U_62_6] Exim Banner 확인" "grep -i '^smtp_banner' \"$EXIM_CONF\" || echo 'none'")
    if [[ "$EXIM_BANNER" == "none" ]]; then
        U_62_6=1
        log_basis "[U_62_6] Exim smtp_banner 설정 미발견" "취약"
    else
        log_basis "[U_62_6] Exim smtp_banner 설정됨: $EXIM_BANNER" "양호"
    fi
else
    U_62_6=0
    TMP=$(run_cmd "[U_62_6] Exim 파일 확인" "ls /etc/exim/exim.conf 2>/dev/null || echo '미존재'")
    log_basis "[U_62_6] Exim 설정 파일 없음" "양호"
fi

# 7. [U_62_7] vsFTP 점검
VS_CONF=""
if [[ -f "/etc/vsftpd.conf" ]]; then VS_CONF="/etc/vsftpd.conf";
elif [[ -f "/etc/vsftpd/vsftpd.conf" ]]; then VS_CONF="/etc/vsftpd/vsftpd.conf"; fi

if [[ -n "$VS_CONF" ]]; then
    VS_BANNER=$(run_cmd "[U_62_7] vsFTP Banner 확인" "grep -i '^ftpd_banner' \"$VS_CONF\" || echo 'none'")
    if [[ "$VS_BANNER" == "none" ]]; then
        U_62_7=1
        log_basis "[U_62_7] vsFTP ftpd_banner 설정 미발견" "취약"
    else
        log_basis "[U_62_7] vsFTP ftpd_banner 설정됨: $VS_BANNER" "양호"
    fi
else
    U_62_7=0
    TMP=$(run_cmd "[U_62_7] vsFTP 파일 확인" "ls /etc/vsftpd.conf 2>/dev/null || echo '미존재'")
    log_basis "[U_62_7] vsFTP 설정 파일 없음" "양호"
fi

# 8. [U_62_8] ProFTP 점검
PRO_CONF=""
if [[ -f "/etc/proftpd/proftpd.conf" ]]; then PRO_CONF="/etc/proftpd/proftpd.conf";
elif [[ -f "/etc/proftpd.conf" ]]; then PRO_CONF="/etc/proftpd.conf"; fi

if [[ -n "$PRO_CONF" ]]; then
    PRO_BANNER=$(run_cmd "[U_62_8] ProFTP Banner 확인" "grep -i 'DisplayLogin' \"$PRO_CONF\" || echo 'none'")
    if [[ "$PRO_BANNER" == "none" ]]; then
        U_62_8=1
        log_basis "[U_62_8] ProFTP DisplayLogin 설정 미발견" "취약"
    else
        log_basis "[U_62_8] ProFTP DisplayLogin 설정됨: $PRO_BANNER" "양호"
    fi
else
    U_62_8=0
    TMP=$(run_cmd "[U_62_8] ProFTP 파일 확인" "ls /etc/proftpd/proftpd.conf 2>/dev/null || echo '미존재'")
    log_basis "[U_62_8] ProFTP 설정 파일 없음" "양호"
fi

# 9. [U_62_9] DNS 점검
BIND_CONF=""
if [[ -f "/etc/bind/named.conf.options" ]]; then BIND_CONF="/etc/bind/named.conf.options";
elif [[ -f "/etc/bind/named.conf" ]]; then BIND_CONF="/etc/bind/named.conf"; fi

if [[ -n "$BIND_CONF" ]]; then
    DNS_VER=$(run_cmd "[U_62_9] DNS Version 설정 확인" "grep -i 'version' \"$BIND_CONF\" || echo 'none'")
    if [[ "$DNS_VER" == "none" ]]; then
        U_62_9=1
        log_basis "[U_62_9] DNS version 설정(정보 숨김) 미발견" "취약"
    else
        log_basis "[U_62_9] DNS version 설정됨: $DNS_VER" "양호"
    fi
else
    U_62_9=0
    TMP=$(run_cmd "[U_62_9] DNS 파일 확인" "ls /etc/bind/named.conf* 2>/dev/null || echo '미존재'")
    log_basis "[U_62_9] DNS 설정 파일 없음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_62_1 -eq 0 && $U_62_2 -eq 0 && $U_62_3 -eq 0 && $U_62_4 -eq 0 && $U_62_5 -eq 0 && $U_62_6 -eq 0 && $U_62_7 -eq 0 && $U_62_8 -eq 0 && $U_62_9 -eq 0 ]]; then
    IS_VUL=0
else
    IS_VUL=1
fi

# JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
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
    "timestamp": "$DATE"
  }
}
EOF