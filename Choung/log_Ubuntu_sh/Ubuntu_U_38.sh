#!/bin/bash

# [U-38] DoS 공격에 이용 가능한 서비스 비활성화 여부 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-38"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_38_1=0; U_38_2=0; U_38_3=0; U_38_4=0; IS_VUL=0

DOS_SERVICES="echo|discard|daytime|chargen|ntp|snmp|dns|named|bind|smtp|sendmail|postfix"
DOS_PORTS_REGEX=":(7|9|13|19|123|161|53|25) "

# 1. [U_38_1] inetd.conf 점검
if [[ -f "/etc/inetd.conf" ]]; then
    I_DOS=$(run_cmd "[U_38_1] inetd.conf 내 DoS 서비스 확인" "grep -v '^#' /etc/inetd.conf | grep -iE '$DOS_SERVICES' || echo 'none'")
    if [[ "$I_DOS" != "none" ]]; then
        U_38_1=1
        log_basis "[U_38_1] inetd.conf에 DoS 취약 서비스 활성화됨" "취약"
    else
        log_basis "[U_38_1] inetd.conf 안전" "양호"
    fi
else
    TMP=$(run_cmd "[U_38_1] inetd.conf 파일 확인" "ls /etc/inetd.conf 2>/dev/null || echo '없음'")
    log_basis "[U_38_1] inetd.conf 파일 없음" "양호"
fi

# 2. [U_38_2] xinetd.d 점검
if [[ -d "/etc/xinetd.d" ]]; then
    X_DOS=$(run_cmd "[U_38_2] xinetd 내 DoS 서비스 확인" "grep -rEi 'disable.*=.*no' /etc/xinetd.d/ 2>/dev/null | grep -iE '$DOS_SERVICES' || echo 'none'")
    if [[ "$X_DOS" != "none" ]]; then
        U_38_2=1
        log_basis "[U_38_2] xinetd에 DoS 취약 서비스 활성화됨" "취약"
    else
        log_basis "[U_38_2] xinetd 안전" "양호"
    fi
else
    TMP=$(run_cmd "[U_38_2] xinetd 디렉터리 확인" "ls -d /etc/xinetd.d 2>/dev/null || echo '없음'")
    log_basis "[U_38_2] xinetd 디렉터리 없음" "양호"
fi

# 3. [U_38_3] systemd 점검
S_DOS=$(run_cmd "[U_38_3] systemd DoS 서비스 유닛 확인" "systemctl list-unit-files 2>/dev/null | grep -iE \"$DOS_SERVICES|chrony\" | grep 'enabled' || echo 'none'")
if [[ "$S_DOS" != "none" ]]; then
    U_38_3=1
    log_basis "[U_38_3] systemd에 DoS 취약 서비스 활성화됨 ($S_DOS)" "취약"
else
    log_basis "[U_38_3] systemd DoS 서비스 비활성" "양호"
fi

# 4. [U_38_4] 포트 점검
P_DOS=$(run_cmd "[U_38_4] DoS 관련 포트 확인" "netstat -antup 2>/dev/null | grep -E '$DOS_PORTS_REGEX' | grep -E 'LISTEN|UDP' || echo 'none'")
if [[ "$P_DOS" != "none" ]]; then
    U_38_4=1
    log_basis "[U_38_4] DoS 관련 포트 오픈됨 ($P_DOS)" "취약"
else
    log_basis "[U_38_4] DoS 관련 포트 미발견" "양호"
fi

if [[ $U_38_1 -eq 1 || $U_38_2 -eq 1 || $U_38_3 -eq 1 || $U_38_4 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-38",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_38_1": $U_38_1,
      "U_38_2": $U_38_2,
      "U_38_3": $U_38_3,
      "U_38_4": $U_38_4
    },
    "timestamp": "$DATE"
  }
}
EOF
