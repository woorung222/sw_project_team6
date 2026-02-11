#!/bin/bash

# [U-48] SMTP 서비스 사용 시 expn, vrfy 명령어 사용 금지 설정 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-48"
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
U_48_1=0; U_48_2=0; U_48_3=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_48_1] Sendmail 점검
if [[ -f "/etc/mail/sendmail.cf" ]]; then
    PRIV_OPT=$(run_cmd "[U_48_1] Sendmail PrivacyOptions 확인" "grep 'PrivacyOptions' /etc/mail/sendmail.cf || echo 'none'")
    
    if [[ "$PRIV_OPT" != "none" ]]; then
        VULN_CHECK=$(echo "$PRIV_OPT" | grep -E "novrfy|noexpn|goaway" || echo "none")
        if [[ "$VULN_CHECK" == "none" ]]; then
            U_48_1=1
            log_basis "[U_48_1] PrivacyOptions 설정($PRIV_OPT)에 제한 옵션 미포함" "취약"
        else
            log_basis "[U_48_1] Sendmail 제한 설정 확인: $PRIV_OPT" "양호"
        fi
    else
        U_48_1=1
        log_basis "[U_48_1] sendmail.cf 내 PrivacyOptions 설정 없음" "취약"
    fi
else
    # [증빙 로그 추가] 파일이 없음을 확인하는 명령어 실행
    TMP=$(run_cmd "[U_48_1] Sendmail 설정 파일 확인" "ls -l /etc/mail/sendmail.cf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_48_1] Sendmail 설정 파일이 존재하지 않음" "양호"
fi

# 2. [U_48_2] Postfix 점검
if [[ -f "/etc/postfix/main.cf" ]]; then
    POSTFIX_VRFY=$(run_cmd "[U_48_2] Postfix disable_vrfy 확인" "grep 'disable_vrfy_command' /etc/postfix/main.cf | grep -i 'yes' || echo 'none'")
    
    if [[ "$POSTFIX_VRFY" == "none" ]]; then
        U_48_2=1
        log_basis "[U_48_2] disable_vrfy_command = yes 설정 미발견" "취약"
    else
        log_basis "[U_48_2] Postfix VRFY 제한 설정 확인: $POSTFIX_VRFY" "양호"
    fi
else
    # [증빙 로그 추가]
    TMP=$(run_cmd "[U_48_2] Postfix 설정 파일 확인" "ls -l /etc/postfix/main.cf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_48_2] Postfix 설정 파일이 존재하지 않음" "양호"
fi

# 3. [U_48_3] Exim 점검
EXIM_CONF=""
if [[ -f "/etc/exim/exim.conf" ]]; then EXIM_CONF="/etc/exim/exim.conf";
elif [[ -f "/etc/exim4/exim4.conf" ]]; then EXIM_CONF="/etc/exim4/exim4.conf"; fi

if [[ -n "$EXIM_CONF" ]]; then
    EXIM_CHECK=$(run_cmd "[U_48_3] Exim ACL 설정 확인" "grep -E 'acl_smtp_vrfy|acl_smtp_expn' \"$EXIM_CONF\" | grep -v '^#' || echo 'none'")
    
    if [[ "$EXIM_CHECK" != "none" ]]; then
        U_48_3=1
        log_basis "[U_48_3] Exim VRFY/EXPN 관련 ACL 설정 존재: $EXIM_CHECK" "취약"
    else
        log_basis "[U_48_3] Exim VRFY/EXPN 관련 ACL 설정 없음" "양호"
    fi
else
    # [증빙 로그 추가]
    TMP=$(run_cmd "[U_48_3] Exim 설정 파일 확인" "ls -l /etc/exim/exim.conf /etc/exim4/exim4.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_48_3] Exim 설정 파일이 존재하지 않음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_48_1 -eq 1 || $U_48_2 -eq 1 || $U_48_3 -eq 1 ]]; then
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
      "U_48_1": $U_48_1,
      "U_48_2": $U_48_2,
      "U_48_3": $U_48_3
    },
    "timestamp": "$DATE"
  }
}
EOF