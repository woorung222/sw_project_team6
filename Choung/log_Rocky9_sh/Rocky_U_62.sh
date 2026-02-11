#!/bin/bash

# [U-62] 로그인 시 경고 메시지 설정
# 대상 운영체제 : Rocky Linux 9

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
U_62_1=0; U_62_2=0; U_62_3=0; U_62_4=0; U_62_5=0; U_62_6=0; U_62_7=0; U_62_8=0; U_62_9=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [Server] 기본 배너 점검 (U_62_1)
# stdout 노출 방지를 위해 run_cmd 결과를 변수에만 담음
L_62_1=$(run_cmd "[U_62_1] /etc/motd, /etc/issue 파일 내용 확인" "ls -s /etc/motd /etc/issue 2>/dev/null")
if [[ ! -s "/etc/motd" ]] && [[ ! -s "/etc/issue" ]]; then
    U_62_1=1
    log_basis "[U_62_1] 서버 로그인 배너(/etc/motd, /etc/issue) 내용이 모두 없음" "취약"
else
    log_basis "[U_62_1] 서버 로그인 배너 설정 양호" "양호"
fi

# 2. [Telnet] 배너 점검 (U_62_2)
if rpm -qa | grep -q "telnet-server"; then
    L_62_2=$(run_cmd "[U_62_2] /etc/issue.net 파일 내용 확인" "ls -s /etc/issue.net 2>/dev/null")
    if [[ ! -s "/etc/issue.net" ]]; then
        U_62_2=1
        log_basis "[U_62_2] Telnet 배너(/etc/issue.net) 내용이 없음" "취약"
    else
        log_basis "[U_62_2] Telnet 배너 설정 양호" "양호"
    fi
else
    log_basis "[U_62_2] Telnet 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 3. [SSH] 배너 점검 (U_62_3)
if [[ -f "/etc/ssh/sshd_config" ]]; then
    # grep 에러 방지를 위해 || true 처리 및 명시적 결과 확인
    S_BANNER=$(run_cmd "[U_62_3] SSH Banner 설정 확인" "grep '^Banner' /etc/ssh/sshd_config | grep -v 'none' || echo '없음'")
    if [[ "$S_BANNER" == "없음" ]]; then
        U_62_3=1
        log_basis "[U_62_3] SSH Banner 설정이 없거나 none으로 설정됨" "취약"
    else
        log_basis "[U_62_3] SSH Banner 설정 양호" "양호"
    fi
else
    log_step "[U_62_3] SSH 설정 파일 확인" "ls /etc/ssh/sshd_config" "파일 없음"
    U_62_3=1
fi

# 4. [Sendmail] 배너 점검 (U_62_4)
if rpm -qa | grep -q "sendmail"; then
    if [[ -f "/etc/mail/sendmail.cf" ]]; then
        SM_BANNER=$(run_cmd "[U_62_4] Sendmail Greeting 확인" "grep 'SmtpGreetingMessage' /etc/mail/sendmail.cf | grep -v '^#' || echo '없음'")
        if [[ "$SM_BANNER" == "없음" ]]; then
            U_62_4=1
            log_basis "[U_62_4] Sendmail Greeting 배너 설정 미흡" "취약"
        else
            log_basis "[U_62_4] Sendmail Greeting 설정 양호" "양호"
        fi
    else
        U_62_4=1
        log_basis "[U_62_4] Sendmail 설정 파일(/etc/mail/sendmail.cf) 없음" "취약"
    fi
else
    log_basis "[U_62_4] Sendmail 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 5. [Postfix] 배너 점검 (U_62_5)
if rpm -qa | grep -q "postfix"; then
    if [[ -f "/etc/postfix/main.cf" ]]; then
        PF_BANNER=$(run_cmd "[U_62_5] Postfix smtpd_banner 확인" "grep '^smtpd_banner' /etc/postfix/main.cf || echo '없음'")
        if [[ "$PF_BANNER" == "없음" ]]; then
            U_62_5=1
            log_basis "[U_62_5] Postfix smtpd_banner 설정 미흡" "취약"
        else
            log_basis "[U_62_5] Postfix smtpd_banner 설정 양호" "양호"
        fi
    else
        U_62_5=1
    fi
else
    log_basis "[U_62_5] Postfix 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 6. [Exim] 배너 점검 (U_62_6)
if rpm -qa | grep -q "exim"; then
    E_CONF=$(ls /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim.conf 2>/dev/null | head -1)
    if [[ -n "$E_CONF" ]]; then
        EX_BANNER=$(run_cmd "[U_62_6] Exim smtp_banner 확인" "grep '^smtp_banner' '$E_CONF' || echo '없음'")
        if [[ "$EX_BANNER" == "없음" ]]; then
            U_62_6=1
            log_basis "[U_62_6] Exim smtp_banner 설정 미흡" "취약"
        else
            log_basis "[U_62_6] Exim smtp_banner 설정 양호" "양호"
        fi
    else
        U_62_6=1
        log_basis "[U_62_6] Exim 설정 파일 없음" "취약"
    fi
else
    log_basis "[U_62_6] Exim 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 7. [vsFTP] 배너 점검 (U_62_7)
if rpm -qa | grep -q "vsftpd"; then
    V_CONF=$(ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1)
    if [[ -n "$V_CONF" ]]; then
        VS_BANNER=$(run_cmd "[U_62_7] vsFTP ftpd_banner 확인" "grep '^ftpd_banner' '$V_CONF' || echo '없음'")
        if [[ "$VS_BANNER" == "없음" ]]; then
            U_62_7=1
            log_basis "[U_62_7] vsFTP ftpd_banner 설정 미흡" "취약"
        else
            log_basis "[U_62_7] vsFTP ftpd_banner 설정 양호" "양호"
        fi
    else
        U_62_7=1
    fi
else
    log_basis "[U_62_7] vsFTP 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 8. [ProFTP] 배너 점검 (U_62_8)
if rpm -qa | grep -q "proftpd"; then
    P_CONF=$(ls /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null | head -1)
    if [[ -n "$P_CONF" ]]; then
        PR_BANNER=$(run_cmd "[U_62_8] ProFTP DisplayLogin 확인" "grep 'DisplayLogin' '$P_CONF' | grep -v '^#' || echo '없음'")
        if [[ "$PR_BANNER" == "없음" ]]; then
            U_62_8=1
            log_basis "[U_62_8] ProFTP DisplayLogin 설정 미흡" "취약"
        else
            log_basis "[U_62_8] ProFTP DisplayLogin 설정 양호" "양호"
        fi
    else
        U_62_8=1
    fi
else
    log_basis "[U_62_8] ProFTP 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 9. [DNS] 배너 점검 (U_62_9)
if rpm -qa | grep -qE "^bind-[0-9]"; then
    if [[ -f "/etc/named.conf" ]]; then
        DNS_VER=$(run_cmd "[U_62_9] DNS version 은폐 확인" "grep 'version' /etc/named.conf | grep -v '^#' || echo '없음'")
        if [[ "$DNS_VER" == "없음" ]]; then
            U_62_9=1
            log_basis "[U_62_9] DNS version 정보 노출 제한 미흡" "취약"
        else
            log_basis "[U_62_9] DNS version 정보 노출 제한 설정됨" "양호"
        fi
    else
        U_62_9=1
    fi
else
    log_basis "[U_62_9] DNS 서비스 미설치 (안 깔려 있음)" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_62_1 -eq 1 || $U_62_2 -eq 1 || $U_62_3 -eq 1 || $U_62_4 -eq 1 || $U_62_5 -eq 1 || $U_62_6 -eq 1 || $U_62_7 -eq 1 || $U_62_8 -eq 1 || $U_62_9 -eq 1 ]]; then
    IS_VUL=1
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-62",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service_management",
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