#!/bin/bash

# [U-01] root 계정 원격 접속 제한
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-01"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then
    source "$BASE_DIR/common_logging.sh"
else
    echo "Warning: common_logging.sh not found." >&2
    run_cmd() { eval "$2"; }
    log_step() { :; }
    log_basis() { :; }
fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

FLAG_U_01_1=0; FLAG_U_01_2=0; IS_VUL=0

# [Telnet 점검 - FLAG_U_01_1]
TELNET_SVC=$(run_cmd "[U-01_1] Telnet 서비스 상태 확인" "systemctl is-active telnet.socket 2>/dev/null || echo 'inactive'")

if [[ "$TELNET_SVC" == "active" ]]; then
    PAM_FILE="/etc/pam.d/login"
    if [[ -f "$PAM_FILE" ]]; then
        PAM_RES=$(run_cmd "[U-01_1] pam_securetty.so 설정 확인" "grep -v '^\s*#' $PAM_FILE | grep 'pam_securetty.so' || echo 'none'")
        if [[ "$PAM_RES" == "none" ]]; then FLAG_U_01_1=1; fi
    else
        TMP=$(run_cmd "[U-01_1] PAM 파일 확인" "ls $PAM_FILE 2>/dev/null || echo '파일 없음'")
        FLAG_U_01_1=1
    fi
    log_basis "[U-01_1] Telnet root 원격 접속 제한 설정 미흡" "$([[ $FLAG_U_01_1 -eq 1 ]] && echo '취약' || echo '양호')"
else
    log_basis "[U-01_1] Telnet 서비스를 사용하고 있지 않음" "양호"
fi

# [SSH 점검 - FLAG_U_01_2]
SSH_SVC=$(run_cmd "[U-01_2] SSH 서비스 상태 확인" "systemctl is-active ssh 2>/dev/null || echo 'inactive'")

if [[ "$SSH_SVC" == "active" ]]; then
    # -Rhis로 조회 후 결과가 없으면(empty) 기본적으로 취약(허용)으로 간주
    PRL_VAL=$(run_cmd "[U-01_2] PermitRootLogin 설정값 확인" "grep -RhisE '^\s*PermitRootLogin\s+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null | tail -n 1 | awk '{print \$2}' | tr '[:upper:]' '[:lower:]' || echo 'not_set'")

    if [[ "$PRL_VAL" == "no" ]]; then
        log_basis "[U-01_2] SSH root 직접 접속 차단 설정(no) 확인됨" "양호"
    else
        FLAG_U_01_2=1
        log_basis "[U-01_2] SSH root 직접 접속이 허용되거나 명시적 설정이 없음 (현재값: $PRL_VAL)" "취약"
    fi
else
    log_basis "[U-01_2] SSH 서비스 미사용 중" "양호"
fi

if [[ $FLAG_U_01_1 -eq 1 || $FLAG_U_01_2 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_01_1": $FLAG_U_01_1,
      "U_01_2": $FLAG_U_01_2
    },
    "timestamp": "$DATE"
  }
}
EOF