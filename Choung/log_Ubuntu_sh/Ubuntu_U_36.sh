#!/bin/bash

# [U-36] r-services(rlogin, rsh, rexec) 관련 패키지 및 서비스 활성화 여부 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-36"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_36_1=0; U_36_2=0; U_36_3=0; U_36_4=0; IS_VUL=0

# 1. [U_36_1] /etc/inetd.conf 점검
if [[ -f "/etc/inetd.conf" ]]; then
    INETD_R=$(run_cmd "[U_36_1] inetd.conf 내 r-service 확인" "grep -E '^\s*(login|shell|exec)\s+' /etc/inetd.conf | grep -v '^#' || echo 'none'")
    if [[ "$INETD_R" != "none" ]]; then
        U_36_1=1
        log_basis "[U_36_1] inetd.conf 내 r-service 활성화됨" "취약"
    else
        log_basis "[U_36_1] inetd.conf 내 r-service 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_36_1] inetd.conf 파일 확인" "ls /etc/inetd.conf 2>/dev/null || echo '없음'")
    log_basis "[U_36_1] inetd.conf 파일 없음" "양호"
fi

# 2. [U_36_2] /etc/xinetd.d/ 점검
if [[ -d "/etc/xinetd.d" ]]; then
    XINETD_R=$(run_cmd "[U_36_2] xinetd 내 r-service 활성 확인" "grep -rEi 'disable.*=.*no' /etc/xinetd.d/ 2>/dev/null | grep -E '(rlogin|rsh|rexec)' || echo 'none'")
    if [[ "$XINETD_R" != "none" ]]; then
        U_36_2=1
        log_basis "[U_36_2] xinetd 내 r-service 활성화됨" "취약"
    else
        log_basis "[U_36_2] xinetd 내 r-service 비활성" "양호"
    fi
else
    TMP=$(run_cmd "[U_36_2] xinetd.d 디렉터리 확인" "ls -d /etc/xinetd.d 2>/dev/null || echo '없음'")
    log_basis "[U_36_2] xinetd.d 디렉터리 없음" "양호"
fi

# 3. [U_36_3] systemd 서비스 점검
SYSTEMD_R=$(run_cmd "[U_36_3] systemd r-service 유닛 확인" "systemctl list-unit-files 2>/dev/null | grep -E '(rlogin|rsh|rexec|shell.target|login.target|exec.target)' | grep 'enabled' || echo 'none'")
if [[ "$SYSTEMD_R" != "none" ]]; then
    U_36_3=1
    log_basis "[U_36_3] systemd 유닛 활성화됨 ($SYSTEMD_R)" "취약"
else
    log_basis "[U_36_3] systemd r-service 유닛 비활성" "양호"
fi

# 4. [U_36_4] 패키지 설치 여부 점검
PKG_R=$(run_cmd "[U_36_4] r-service 관련 패키지 확인" "dpkg -l | grep -E 'rsh-server|rsh-redone-server|rsh-client|rlogin|rexec' | grep '^ii' | awk '{print \$2}' || echo 'none'")
if [[ "$PKG_R" != "none" ]]; then
    U_36_4=1
    log_basis "[U_36_4] r-service 관련 패키지 설치됨 ($PKG_R)" "취약"
else
    log_basis "[U_36_4] r-service 관련 패키지 미설치" "양호"
fi

if [[ $U_36_1 -eq 1 || $U_36_2 -eq 1 || $U_36_3 -eq 1 || $U_36_4 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-36",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_36_1": $U_36_1,
      "U_36_2": $U_36_2,
      "U_36_3": $U_36_3,
      "U_36_4": $U_36_4
    },
    "timestamp": "$DATE"
  }
}
EOF
