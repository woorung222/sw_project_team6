#!/bin/bash

# [U-62] 로그인 시 경고 메시지 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.150-158
# 자동 조치 가능 유무 : 불가능 (정책에 맞는 경고 문구 작성 필요)
# 플래그 설명:
#   U_62_1 : [Server] /etc/motd, /etc/issue 파일 내용 없음
#   U_62_2 : [Telnet] /etc/issue.net 파일 내용 없음
#   U_62_3 : [SSH] sshd_config 내 Banner 설정 미흡
#   U_62_4 : [Sendmail] SmtpGreetingMessage 설정 미흡
#   U_62_5 : [Postfix] smtpd_banner 설정 미흡
#   U_62_6 : [Exim] smtp_banner 설정 미흡
#   U_62_7 : [vsFTP] ftpd_banner 설정 미흡
#   U_62_8 : [ProFTP] DisplayLogin 설정 미흡
#   U_62_9 : [DNS] named.conf 내 version 설정 미흡

# --- 점검 로직 시작 ---

# 초기화
U_62_1=0
U_62_2=0
U_62_3=0
U_62_4=0
U_62_5=0
U_62_6=0
U_62_7=0
U_62_8=0
U_62_9=0

# 1. [Server] 기본 배너 점검 (U_62_1)
# 파일이 존재하고 내용이 있어야(-s) 양호
if [[ ! -s "/etc/motd" ]] && [[ ! -s "/etc/issue" ]]; then
    U_62_1=1
fi

# 2. [Telnet] 배너 점검 (U_62_2)
if rpm -qa | grep -q "telnet-server"; then
    if [[ ! -s "/etc/issue.net" ]]; then
        U_62_2=1
    fi
fi

# 3. [SSH] 배너 점검 (U_62_3)
if [[ -f "/etc/ssh/sshd_config" ]]; then
    # Banner 설정이 주석 해제되어 있고 값이 설정되어 있는지 확인
    if ! grep "^Banner" "/etc/ssh/sshd_config" | grep -v "none" >/dev/null 2>&1; then
        U_62_3=1
    fi
fi

# 4. [Sendmail] 배너 점검 (U_62_4)
if rpm -qa | grep -qE "^sendmail-[0-9]"; then
    if [[ -f "/etc/mail/sendmail.cf" ]]; then
        if ! grep "SmtpGreetingMessage" "/etc/mail/sendmail.cf" | grep -v "^#" >/dev/null 2>&1; then
            U_62_4=1
        fi
    fi
fi

# 5. [Postfix] 배너 점검 (U_62_5)
if rpm -qa | grep -qE "^postfix-[0-9]"; then
    if [[ -f "/etc/postfix/main.cf" ]]; then
        if ! grep "^smtpd_banner" "/etc/postfix/main.cf" >/dev/null 2>&1; then
            U_62_5=1
        fi
    fi
fi

# 6. [Exim] 배너 점검 (U_62_6) - 신규 추가
if rpm -qa | grep -q "exim"; then
    EXIM_CONF=""
    # 설정 파일 경로 탐색
    if [[ -f "/etc/exim/exim.conf" ]]; then EXIM_CONF="/etc/exim/exim.conf";
    elif [[ -f "/etc/exim4/exim4.conf" ]]; then EXIM_CONF="/etc/exim4/exim4.conf";
    elif [[ -f "/etc/exim.conf" ]]; then EXIM_CONF="/etc/exim.conf"; fi

    if [[ -n "$EXIM_CONF" ]]; then
        # smtp_banner 설정 확인 (주석 제외)
        if ! grep "^smtp_banner" "$EXIM_CONF" >/dev/null 2>&1; then
            U_62_6=1
        fi
    else
        # 패키지는 있는데 설정 파일이 없으면 점검 불가(취약 간주)
        U_62_6=1
    fi
fi

# 7. [vsFTP] 배너 점검 (U_62_7)
if rpm -qa | grep -q "vsftpd"; then
    VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
    [[ ! -f "$VSFTP_CONF" ]] && VSFTP_CONF="/etc/vsftpd.conf"
    
    if [[ -f "$VSFTP_CONF" ]]; then
        if ! grep "^ftpd_banner" "$VSFTP_CONF" >/dev/null 2>&1; then
            U_62_7=1
        fi
    fi
fi

# 8. [ProFTP] 배너 점검 (U_62_8)
if rpm -qa | grep -q "proftpd"; then
    PROFTP_CONF="/etc/proftpd.conf"
    [[ ! -f "$PROFTP_CONF" ]] && PROFTP_CONF="/etc/proftpd/proftpd.conf"
    
    if [[ -f "$PROFTP_CONF" ]]; then
        if ! grep "DisplayLogin" "$PROFTP_CONF" | grep -v "^#" >/dev/null 2>&1; then
            U_62_8=1
        fi
    fi
fi

# 9. [DNS] 배너 점검 (U_62_9)
if rpm -qa | grep -qE "^bind-[0-9]"; then
    if [[ -f "/etc/named.conf" ]]; then
        # version 설정(정보 은폐) 확인
        if ! grep "version" "/etc/named.conf" | grep -v "^#" >/dev/null 2>&1; then
            U_62_9=1
        fi
    fi
fi

# 10. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_62_1 -eq 1 ]] || [[ $U_62_2 -eq 1 ]] || [[ $U_62_3 -eq 1 ]] || \
   [[ $U_62_4 -eq 1 ]] || [[ $U_62_5 -eq 1 ]] || [[ $U_62_6 -eq 1 ]] || \
   [[ $U_62_7 -eq 1 ]] || [[ $U_62_8 -eq 1 ]] || [[ $U_62_9 -eq 1 ]]; then
    IS_VUL=1
fi

# 11. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-62",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service_management",
    "flags": {
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
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
