#!/bin/bash

# [U-58] SNMP 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-58"
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
U_58_1=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_58_1] SNMP 서비스 활성화 여부 확인
# systemctl로 서비스 상태 확인
SNMP_CHECK=$(run_cmd "[U_58_1] snmpd 서비스 확인" "systemctl list-units --type=service 2>/dev/null | grep 'snmpd' || echo 'none'")

if [[ "$SNMP_CHECK" != "none" ]]; then
    U_58_1=1
    log_basis "[U_58_1] snmpd 서비스가 활성화되어 있음: $SNMP_CHECK" "취약"
else
    log_basis "[U_58_1] snmpd 서비스 비활성화 (프로세스 미발견)" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_58_1 -eq 1 ]]; then
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
      "U_58_1": $U_58_1
    },
    "timestamp": "$DATE"
  }
}
EOF
