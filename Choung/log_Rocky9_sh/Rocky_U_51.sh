#!/bin/bash

# [U-51] DNS 서비스의 취약한 동적 업데이트 설정 금지
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-51"
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
U_51_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

S_NAMED=$(run_cmd "[51] named 서비스 활성 확인" "systemctl is-active named 2>/dev/null || echo 'inactive'")
if [[ "$S_NAMED" == "active" ]]; then
    NAMED_CONF="/etc/named.conf"
    if [[ -f "$NAMED_CONF" ]]; then
        ALLOW_UPD=$(run_cmd "[U_51_1] allow-update 설정 확인" "grep -vE '^#|^//' '$NAMED_CONF' | grep 'allow-update' || echo '미설정'")
        if [[ "$ALLOW_UPD" == *"any"* ]]; then
            U_51_1=1
            log_basis "[U_51_1] 동적 업데이트 설정이 전체 허용(any)되어 취약함" "취약"
        else
            log_basis "[U_51_1] 동적 업데이트 설정 양호" "양호"
        fi
    else
        log_step "[U_51_1] 설정 파일 확인" "ls $NAMED_CONF" "파일 없음"
        log_basis "[U_51_1] DNS 서비스가 활성 상태이나 설정 파일이 없어 점검 불가" "취약"
    fi
else
    log_basis "[U_51_1] DNS 서비스가 활성화되어 있지 않음 (안 깔려 있음)" "양호"
fi

IS_VUL=$U_51_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_51_1": $U_51_1
    },
    "timestamp": "$DATE"
  }
}
EOF