#!/bin/bash

# [U-43] NIS 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9

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
NIS_TARGETS=("ypserv" "ypbind" "ypxfrd" "rpc.yppasswdd" "rpc.ypupdated")
NIS_REGEX=$(IFS="|"; echo "${NIS_TARGETS[*]}")

# --- 점검 로직 시작 ---

# 1. [U_43_1] systemd 점검
S_NIS=$(run_cmd "[U_43_1] systemd NIS 유닛(service/socket) 활성 확인" "systemctl list-units --type service,socket 2>/dev/null | grep -E '$NIS_REGEX' | grep -w 'active'")
if [[ -n "$S_NIS" ]]; then U_43_1=1; fi

# 2. [U_43_1] Process 점검 (systemd에서 누락된 경우)
if [[ $U_43_1 -eq 0 ]]; then
    for svc in "${NIS_TARGETS[@]}"; do
        P_NIS=$(run_cmd "[U_43_1] $svc 프로세스 실행 여부 확인" "ps -e -o comm | grep -xw '$svc'")
        if [[ -n "$P_NIS" ]]; then U_43_1=1; break; fi
    done
fi
log_basis "[U_43_1] NIS 관련 서비스/프로세스 활성화 여부" "$([[ $U_43_1 -eq 1 ]] && echo '취약' || echo '양호')"

IS_VUL=$U_43_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
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
