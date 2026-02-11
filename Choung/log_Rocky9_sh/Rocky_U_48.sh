#!/bin/bash

# [U-48] expn, vrfy 명령어 제한
# 대상 운영체제 : Rocky Linux 9

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

# --- 점검 로직 시작 ---

M_ACT=$(run_cmd "[48] 메일 서비스(Sendmail, Postfix, Exim) 활성 상태 확인" "systemctl is-active sendmail postfix exim 2>/dev/null | grep 'active' || echo '안 깔려 있음'")

if [[ "$M_ACT" != "안 깔려 있음" ]]; then

    # 1. [Sendmail] 점검 (U_48_1)
    if systemctl is-active sendmail >/dev/null 2>&1; then
        CF_FILE="/etc/mail/sendmail.cf"
        if [[ -f "$CF_FILE" ]]; then
            PRIV_OPTS=$(run_cmd "[U_48_1] Sendmail PrivacyOptions 확인" "grep -v '^#' '$CF_FILE' | grep 'PrivacyOptions' || echo '미설정'")
            if [[ "$PRIV_OPTS" == *"goaway"* ]] || ([[ "$PRIV_OPTS" == *"noexpn"* ]] && [[ "$PRIV_OPTS" == *"novrfy"* ]]); then
                log_basis "[U_48_1] Sendmail expn/vrfy 설정 양호" "양호"
            else
                U_48_1=1
                log_basis "[U_48_1] Sendmail PrivacyOptions 설정 미흡" "취약"
            fi
        else
            log_step "[U_48_1] 파일 확인" "ls $CF_FILE" "파일 없음"
            U_48_1=1
        fi
    else
        log_basis "[U_48_1] Sendmail 서비스가 활성화되어 있지 않음 (안 깔려 있음)" "양호"
    fi

    # 2. [Postfix] 점검 (U_48_2)
    if systemctl is-active postfix >/dev/null 2>&1; then
        P_VRFY=$(run_cmd "[U_48_2] Postfix vrfy 제한 확인" "postconf -h disable_vrfy_command 2>/dev/null || echo 'no'")
        if [[ "$P_VRFY" == "yes" ]]; then
            log_basis "[U_48_2] Postfix disable_vrfy_command 설정 양호" "양호"
        else
            U_48_2=1
            log_basis "[U_48_2] Postfix disable_vrfy_command 미설정" "취약"
        fi
    else
        log_basis "[U_48_2] Postfix 서비스가 활성화되어 있지 않음 (안 깔려 있음)" "양호"
    fi

    # 3. [Exim] 점검 (U_48_3)
    if systemctl is-active exim >/dev/null 2>&1; then
        E_CONF=$(run_cmd "[U_48_3] Exim 설정 파일 확인" "exim -bV 2>/dev/null | grep 'Configuration file' | awk '{print \$3}'")
        if [[ -f "$E_CONF" ]]; then
            E_CHECK=$(run_cmd "[U_48_3] Exim vrfy/expn 설정 확인" "grep -E 'acl_smtp_vrfy|acl_smtp_expn' '$E_CONF' 2>/dev/null | grep -v '^#' | grep 'accept' || echo '제한됨'")
            if [[ "$E_CHECK" != "제한됨" ]]; then
                U_48_3=1
                log_basis "[U_48_3] Exim vrfy/expn 허용 설정 발견" "취약"
            else
                log_basis "[U_48_3] Exim vrfy/expn 설정 양호" "양호"
            fi
        fi
    else
        log_basis "[U_48_3] Exim 서비스가 활성화되어 있지 않음 (안 깔려 있음)" "양호"
    fi
else
    log_basis "[U_48_1] 메일 서비스 미사용 (안 깔려 있음)" "양호"
    log_basis "[U_48_2] 메일 서비스 미사용 (안 깔려 있음)" "양호"
    log_basis "[U_48_3] 메일 서비스 미사용 (안 깔려 있음)" "양호"
fi

if [[ $U_48_1 -eq 1 || $U_48_2 -eq 1 || $U_48_3 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 0,
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