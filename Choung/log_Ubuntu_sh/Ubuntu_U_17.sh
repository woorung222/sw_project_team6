#!/bin/bash

# [U-17] 시스템 시작 스크립트 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-17"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_17_1=0; U_17_2=0; IS_VUL=0

# [U_17_1] init.d 디렉터리 점검
INIT_DIR="/etc/rc.d"
CHECK_INIT=$(run_cmd "[U_17_1] $INIT_DIR 디렉터리 확인" "ls -d $INIT_DIR 2>/dev/null || echo '디렉터리 없음'")
if [[ "$CHECK_INIT" != "디렉터리 없음" ]]; then
    VULN_I=$(run_cmd "[U_17_1] $INIT_DIR 내 권한 미흡 파일 검색" "find -L '$INIT_DIR' -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null")
    if [[ -n "$VULN_I" ]]; then
        U_17_1=1
        log_basis "[U_17_1] init 시작 스크립트 중 소유자가 root가 아니거나 쓰기 권한이 발견됨" "취약"
    else
        log_basis "[U_17_1] init 시작 스크립트 설정 양호" "양호"
    fi
else
    log_basis "[U_17_1] $INIT_DIR 디렉터리가 존재하지 않음 (안 깔려 있음)" "양호"
fi

# [U_17_2] systemd 디렉터리 점검
SYSTEMD_DIR="/etc/systemd/system"
CHECK_SYS=$(run_cmd "[U_17_2] $SYSTEMD_DIR 디렉터리 확인" "ls -d $SYSTEMD_DIR 2>/dev/null || echo '디렉터리 없음'")
if [[ "$CHECK_SYS" != "디렉터리 없음" ]]; then
    VULN_S=$(run_cmd "[U_17_2] $SYSTEMD_DIR 내 권한 미흡 파일 검색" "find -L '$SYSTEMD_DIR' -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null")
    if [[ -n "$VULN_S" ]]; then
        U_17_2=1
        log_basis "[U_17_2] systemd 유닛 파일 중 소유자 또는 쓰기 권한 설정이 미흡함" "취약"
    else
        log_basis "[U_17_2] systemd 서비스 유닛 파일 설정 양호" "양호"
    fi
else
    log_basis "[U_17_2] systemd 디렉터리가 존재하지 않음 (안 깔려 있음)" "양호"
fi

if [[ $U_17_1 -eq 1 ]] || [[ $U_17_2 -eq 1 ]]; then IS_VUL=1; fi

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
    "category": "file",
    "flag": {
      "U_17_1": $U_17_1,
      "U_17_2": $U_17_2
    },
    "timestamp": "$DATE"
  }
}
EOF