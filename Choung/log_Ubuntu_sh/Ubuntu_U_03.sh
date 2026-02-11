#!/bin/bash

# [U-03] 계정 잠금 임계값 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-03"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_03_1=1; IS_VUL=0

# 1. pam_faillock 적용 여부 확인
PAM_AUTH="/etc/pam.d/common-auth"
HAS_FAILLOCK=$(run_cmd "[U_03_1] pam_faillock.so 모듈 적용 확인" "grep -v '^\s*#' $PAM_AUTH 2>/dev/null | grep -qE '\bpam_faillock\.so\b' && echo 'set' || echo 'not_set'")

# 2. 임계값 설정 확인
CONF="/etc/security/faillock.conf"
DENY_VAL=$(run_cmd "[U_03_1] 계정 잠금 임계값(deny) 확인" "grep -v '^\s*#' $CONF 2>/dev/null | grep -E '^\s*deny\s*=' | tail -n 1 | awk -F= '{print \$2}' | tr -d ' ' || echo 'not_set'")
UNLOCK_TIME=$(run_cmd "[U_03_1] 잠금 해제 시간(unlock_time) 확인" "grep -v '^\s*#' $CONF 2>/dev/null | grep -E '^\s*unlock_time\s*=' | tail -n 1 | awk -F= '{print \$2}' | tr -d ' ' || echo 'not_set'")

# 판정
OK_DENY=0; OK_UNLOCK=0
if [[ "$DENY_VAL" =~ ^[0-9]+$ ]] && [ "$DENY_VAL" -ge 1 ] && [ "$DENY_VAL" -le 10 ]; then OK_DENY=1; fi
if [[ "$UNLOCK_TIME" =~ ^[0-9]+$ ]] && [ "$UNLOCK_TIME" -ge 0 ]; then OK_UNLOCK=1; fi

if [[ "$HAS_FAILLOCK" == "set" ]] && [ "$OK_DENY" -eq 1 ] && [ "$OK_UNLOCK" -eq 1 ]; then
    U_03_1=0
    log_basis "[U_03_1] 계정 잠금 임계값 설정 양호 (deny: $DENY_VAL, unlock_time: $UNLOCK_TIME)" "양호"
else
    U_03_1=1
    log_basis "[U_03_1] 계정 잠금 설정 미흡 (deny: $DENY_VAL, unlock_time: $UNLOCK_TIME)" "취약"
fi

IS_VUL=$U_03_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_03_1": $U_03_1
    },
    "timestamp": "$DATE"
  }
}
EOF
