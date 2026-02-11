#!/bin/bash

# [U-58] 불필요한 SNMP 서비스 구동 점검
# 대상 운영체제 : Rocky Linux 9

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

# --- 점검 로직 시작 ---

# 1. SNMP 서비스 활성화 여부 점검 (U_58_1)
# systemd 서비스 상태 확인 과정을 run_cmd로 기록
S_ACT=$(run_cmd "[U_58_1] snmpd 서비스 활성 상태 확인" "systemctl is-active snmpd 2>/dev/null || echo 'inactive'")

if [[ "$S_ACT" == "active" ]]; then
    U_58_1=1
    log_basis "[U_58_1] SNMP 서비스(snmpd)가 활성화되어 있어 취약함" "취약"
else
    # 2. 프로세스 실행 여부 확인 (서비스 데몬이 아닌 수동 실행 등 포함)
    # ps 커맨드 실행 과정을 run_cmd로 기록
    PRC_RES=$(run_cmd "[U_58_1] snmpd 프로세스 실행 여부 확인" "ps -ef | grep -v grep | grep -q 'snmpd' && echo '실행 중' || echo '안 깔려 있음'")
    
    if [[ "$PRC_RES" == "실행 중" ]]; then
        U_58_1=1
        log_basis "[U_58_1] SNMP 서비스 프로세스가 실행 중으로 취약함" "취약"
    else
        log_basis "[U_58_1] SNMP 서비스가 비활성화되어 있고 프로세스도 존재하지 않음 (안 깔려 있음)" "양호"
    fi
fi

# 3. 전체 취약 여부 판단
IS_VUL=$U_58_1

# 4. JSON 출력 (원본 구조 및 플래그 명칭 절대 유지)
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-58",
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
