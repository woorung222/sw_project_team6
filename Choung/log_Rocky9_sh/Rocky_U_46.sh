#!/bin/bash

# [U-46] 일반 사용자의 메일 서비스 실행 방지
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-46"
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
U_46_1=0; U_46_2=0; U_46_3=0; IS_VUL=0

# 1. [Sendmail] 점검 (U_46_1)
S_ACT=$(run_cmd "[U_46_1] Sendmail 활성 상태 확인" "systemctl is-active sendmail 2>/dev/null || echo 'inactive'")
if [[ "$S_ACT" == "active" ]]; then
    if [[ -f "/etc/mail/sendmail.cf" ]]; then
        S_PRIV=$(run_cmd "[U_46_1] Sendmail PrivacyOptions 확인" "grep -v '^#' /etc/mail/sendmail.cf | grep -i 'PrivacyOptions' | grep -i 'restrictqrun' || echo '누락'")
        if [[ "$S_PRIV" == "누락" ]]; then U_46_1=1; fi
    else
        log_step "[U_46_1] 설정 파일 확인" "ls /etc/mail/sendmail.cf" "파일 없음"
        U_46_1=1
    fi
fi
log_basis "[U_46_1] Sendmail restrictqrun 설정 여부" "$([[ $U_46_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [Postfix] 점검 (U_46_2)
P_ACT=$(run_cmd "[U_46_2] Postfix 활성 상태 확인" "systemctl is-active postfix 2>/dev/null || echo 'inactive'")
if [[ "$P_ACT" == "active" ]]; then
    if [[ -f "/usr/sbin/postsuper" ]]; then
        P_PERM=$(run_cmd "[U_46_2] postsuper 권한 확인" "stat -c '%a' /usr/sbin/postsuper")
        if [[ $(( ${P_PERM: -1} % 2 )) -eq 1 ]]; then U_46_2=1; fi
    fi
fi
log_basis "[U_46_2] Postfix postsuper 실행 권한 통제 여부" "$([[ $U_46_2 -eq 1 ]] && echo '취약' || echo '양호')"

# 3. [Exim] 점검 (U_46_3)
E_ACT=$(run_cmd "[U_46_3] Exim 활성 상태 확인" "systemctl is-active exim 2>/dev/null || echo 'inactive'")
if [[ "$E_ACT" == "active" ]]; then
    if [[ -f "/usr/sbin/exiqgrep" ]]; then
        E_PERM=$(run_cmd "[U_46_3] exiqgrep 권한 확인" "stat -c '%a' /usr/sbin/exiqgrep")
        if [[ $(( ${E_PERM: -1} % 2 )) -eq 1 ]]; then U_46_3=1; fi
    fi
fi
log_basis "[U_46_3] Exim exiqgrep 실행 권한 통제 여부" "$([[ $U_46_3 -eq 1 ]] && echo '취약' || echo '양호')"

if [[ $U_46_1 -eq 1 || $U_46_2 -eq 1 || $U_46_3 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_46_1": $U_46_1,
      "U_46_2": $U_46_2,
      "U_46_3": $U_46_3
    },
    "timestamp": "$DATE"
  }
}
EOF
