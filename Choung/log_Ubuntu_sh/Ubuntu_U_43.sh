#!/bin/bash

# [U-43] NIS 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-43"
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
U_43_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [U_43_1] NIS 관련 프로세스 및 서비스 유닛 확인
# 프로세스 확인
PROC_CHECK=$(run_cmd "[U_43_1] NIS 관련 프로세스 확인" "ps -ef | grep -iE 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated' | grep -v 'grep' || echo 'none'")

# Systemd 유닛 확인
UNIT_CHECK=$(run_cmd "[U_43_1] NIS 관련 서비스 유닛 확인" "systemctl list-unit-files 2>/dev/null | grep -iE 'ypserv|ypbind|ypxfrd|yppasswdd|ypupdated|nis' | grep 'enabled' || echo 'none'")

if [[ "$PROC_CHECK" != "none" ]] || [[ "$UNIT_CHECK" != "none" ]]; then
    U_43_1=1
    log_basis "[U_43_1] NIS 관련 서비스(프로세스 또는 Systemd)가 활성화되어 있음" "취약"
else
    log_basis "[U_43_1] NIS 관련 서비스 미사용" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_43_1 -eq 1 ]]; then
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
      "U_43_1": $U_43_1
    },
    "timestamp": "$DATE"
  }
}
EOF
