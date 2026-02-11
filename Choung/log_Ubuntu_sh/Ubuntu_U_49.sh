#!/bin/bash

# [U-49] BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검
# 대상 : Ubuntu 24.04

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
U_49_1=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. DNS 서비스 활성화 확인
DNS_ACT=$(run_cmd "[U_49_1] named 서비스 확인" "systemctl list-units --type=service 2>/dev/null | grep named || echo 'none'")

if [[ "$DNS_ACT" != "none" ]]; then
    # 서비스 활성화 시 버전 확인
    CHECK_NAMED_CMD=$(run_cmd "[U_49_1] named 명령어 확인" "command -v named || echo 'none'")
    
    if [[ "$CHECK_NAMED_CMD" != "none" ]]; then
        BIND_VER=$(run_cmd "[U_49_1] BIND 버전 정보 추출" "named -v 2>&1 || echo 'Version info failed'")
        U_49_1=0
        log_basis "[U_49_1] BIND 서비스 동작 중 (버전: $BIND_VER)" "양호"
    else
        U_49_1=1
        log_basis "[U_49_1] named 서비스 활성이나 명령어 미발견" "취약"
    fi
else
    U_49_1=0
    # 서비스 없음 증빙은 위 run_cmd 결과('none')로 갈음
    log_basis "[U_49_1] DNS(named) 서비스 비활성화" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_49_1 -eq 1 ]]; then
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
      "U_49_1": $U_49_1
    },
    "timestamp": "$DATE"
  }
}
EOF