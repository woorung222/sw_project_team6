#!/bin/bash

# [U-49] DNS 보안 버전 패치
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-49"
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
U_49_1=0; U_49_2=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [U_49_1] DNS 서비스 상태 점검
S_NAMED=$(run_cmd "[U_49_1] named 서비스 활성 확인" "systemctl is-active named 2>/dev/null || echo 'inactive'")
if [[ "$S_NAMED" == "active" ]]; then
    U_49_1=1
    # 2. [U_49_2] 버전 업데이트 필요 여부 점검
    UPD_NAMED=$(run_cmd "[U_49_2] bind 패키지 업데이트 확인" "dnf check-update bind -q 2>/dev/null | grep -w bind || echo '최신'")
    if [[ "$UPD_NAMED" != "최신" ]]; then
        U_49_2=1
        log_basis "[U_49_2] DNS 보안 업데이트가 필요함" "취약"
    else
        log_basis "[U_49_2] DNS 서비스 버전이 최신임" "양호"
    fi
else
    log_basis "[U_49_1] DNS 서비스가 활성화되어 있지 않음 (안 깔려 있음)" "양호"
    log_basis "[U_49_2] DNS 서비스 미사용으로 보안 패치 대상 아님 (안 깔려 있음)" "양호"
fi

if [[ $U_49_2 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_49_1": $U_49_1,
      "U_49_2": $U_49_2
    },
    "timestamp": "$DATE"
  }
}
EOF