#!/bin/bash

# [U-47] SMTP 서버의 릴레이 기능 제한 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-47"
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
U_47_1=0; U_47_2=0; U_47_3=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_47_1] Sendmail 점검
if command -v sendmail >/dev/null 2>&1; then
    # 버전 및 로직 확인 (기존과 동일)
    SENDMAIL_VER_FULL=$(run_cmd "[U_47_1] Sendmail 버전 확인" "sendmail -d0.1 -bt < /dev/null 2>&1 | grep 'Version' | awk '{print \$2}' || echo '0.0'")
    SENDMAIL_VER_MAJOR=$(echo "$SENDMAIL_VER_FULL" | cut -d. -f1,2)
    
    IS_LEGACY=0
    if command -v bc > /dev/null; then
        IS_LEGACY=$(echo "$SENDMAIL_VER_MAJOR < 8.9" | bc -l 2>/dev/null)
    fi

    if [[ "$IS_LEGACY" == "1" ]]; then
        RELAY_DENY_CHECK=$(run_cmd "[U_47_1] Relaying denied 확인" "grep 'R$\*' /etc/mail/sendmail.cf 2>/dev/null | grep 'Relaying denied' || echo 'none'")
        if [[ "$RELAY_DENY_CHECK" == "none" ]]; then
            U_47_1=1
            log_basis "[U_47_1] Sendmail(구버전) Relaying denied 설정 미발견" "취약"
        else
            log_basis "[U_47_1] Sendmail(구버전) 릴레이 제한 설정됨" "양호"
        fi
    else
        # 8.9 이상
        if [[ -f "/etc/mail/sendmail.mc" ]]; then
            RELAY_FEATURE=$(run_cmd "[U_47_1] promiscuous_relay 확인" "grep 'FEATURE.*promiscuous_relay' /etc/mail/sendmail.mc || echo 'none'")
            if [[ "$RELAY_FEATURE" != "none" ]]; then
                U_47_1=1
                log_basis "[U_47_1] Sendmail 릴레이 허용(promiscuous_relay) 설정됨" "취약"
            else
                log_basis "[U_47_1] Sendmail 릴레이 허용 설정 없음" "양호"
            fi
        else
            # 파일 없음 증빙
            TMP=$(run_cmd "[U_47_1] sendmail.mc 파일 확인" "ls /etc/mail/sendmail.mc 2>/dev/null || echo '파일 미존재'")
            log_basis "[U_47_1] sendmail.mc 파일 없음" "양호"
        fi
    fi
else
    # 명령 없음 증빙
    TMP=$(run_cmd "[U_47_1] Sendmail 설치 확인" "command -v sendmail || echo '미설치'")
    log_basis "[U_47_1] Sendmail 미설치" "양호"
fi

# 2. [U_47_2] Postfix 점검
if [[ -f "/etc/postfix/main.cf" ]]; then
    POSTFIX_RELAY=$(run_cmd "[U_47_2] Postfix 릴레이 설정 확인" "grep -E 'smtpd_recipient_restrictions|mynetworks' /etc/postfix/main.cf || echo 'none'")
    if [[ "$POSTFIX_RELAY" == "none" ]]; then
        U_47_2=1
        log_basis "[U_47_2] Postfix 릴레이 제한 설정 미흡" "취약"
    else
        log_basis "[U_47_2] Postfix 릴레이 제한 설정 확인: $POSTFIX_RELAY" "양호"
    fi
else
    # 파일 없음 증빙
    TMP=$(run_cmd "[U_47_2] Postfix 설정 파일 확인" "ls /etc/postfix/main.cf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_47_2] Postfix 설정 파일 없음" "양호"
fi

# 3. [U_47_3] Exim 점검
EXIM_CONF=""
if [[ -f "/etc/exim/exim.conf" ]]; then EXIM_CONF="/etc/exim/exim.conf";
elif [[ -f "/etc/exim4/exim4.conf" ]]; then EXIM_CONF="/etc/exim4/exim4.conf"; fi

if [[ -n "$EXIM_CONF" ]]; then
    EXIM_RELAY=$(run_cmd "[U_47_3] Exim 릴레이 설정 확인" "grep -E 'relay_from_hosts|hosts=' \"$EXIM_CONF\" || echo 'none'")
    if [[ "$EXIM_RELAY" == "none" ]]; then
        U_47_3=1
        log_basis "[U_47_3] Exim 릴레이 제한 설정 미흡" "취약"
    else
        log_basis "[U_47_3] Exim 릴레이 제한 설정 확인: $EXIM_RELAY" "양호"
    fi
else
    # 파일 없음 증빙
    TMP=$(run_cmd "[U_47_3] Exim 설정 파일 확인" "ls -l /etc/exim/exim.conf /etc/exim4/exim4.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_47_3] Exim 설정 파일 없음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_47_1 -eq 1 || $U_47_2 -eq 1 || $U_47_3 -eq 1 ]]; then
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
      "U_47_1": $U_47_1,
      "U_47_2": $U_47_2,
      "U_47_3": $U_47_3
    },
    "timestamp": "$DATE"
  }
}
EOF