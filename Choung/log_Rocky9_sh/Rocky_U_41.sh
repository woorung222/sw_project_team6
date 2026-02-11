#!/bin/bash

# [U-41] 불필요한 automountd 제거
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-41"
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
U_41_1=0; U_41_2=0; IS_VUL=0

# 1. [U_41_1] Running 상태 점검
SVC_A=$(run_cmd "[U_41_1] autofs 서비스 활성 여부 확인" "systemctl is-active autofs 2>/dev/null")
PRC_A=$(run_cmd "[U_41_1] autofs 프로세스 실행 확인" "ps -ef | grep -v grep | grep -E 'automount|autofs'")
if [[ "$SVC_A" == "active" ]] || [[ -n "$PRC_A" ]]; then U_41_1=1; fi
log_basis "[U_41_1] automountd(autofs) 실행 여부" "$([[ $U_41_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [U_41_2] Boot 설정 점검
SVC_E=$(run_cmd "[U_41_2] autofs 자동 실행(enabled) 설정 확인" "systemctl is-enabled autofs 2>/dev/null")
if [[ "$SVC_E" == "enabled" ]]; then U_41_2=1; fi
log_basis "[U_41_2] autofs 부팅 시 자동 실행 여부" "$([[ $U_41_2 -eq 1 ]] && echo '취약' || echo '양호')"

if [[ $U_41_1 -eq 1 ]] || [[ $U_41_2 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_41_1": $U_41_1,
      "U_41_2": $U_41_2
    },
    "timestamp": "$DATE"
  }
}
EOF
