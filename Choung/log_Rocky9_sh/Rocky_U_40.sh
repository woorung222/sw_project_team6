#!/bin/bash

# [U-40] NFS 접근 통제
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-40"
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
U_40_1=0; U_40_2=0; IS_VUL=0
EXPORTS_FILE="/etc/exports"

# 1. [U_40_1] 파일 권한 점검
if [[ -f "$EXPORTS_FILE" ]]; then
    O=$(run_cmd "[U_40_1] exports 소유자 확인" "stat -c '%U' '$EXPORTS_FILE'")
    P=$(run_cmd "[U_40_1] exports 권한 확인" "stat -c '%a' '$EXPORTS_FILE'")
    if [[ "$O" != "root" ]] || [[ "$P" -gt 644 ]]; then U_40_1=1; fi
else
    log_step "[U_40_1] 파일 확인" "ls $EXPORTS_FILE" "파일 없음"
fi
log_basis "[U_40_1] exports 소유자/권한 취약 여부" "$([[ $U_40_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [U_40_2] 접근 설정 점검
if [[ -f "$EXPORTS_FILE" ]]; then
    E_RES=$(run_cmd "[U_40_2] '*' 전체 호스트 허용 여부 확인" "grep -v '^#' '$EXPORTS_FILE' | grep -F '*'")
    if [[ -n "$E_RES" ]]; then U_40_2=1; fi
else
    log_step "[U_40_2] 파일 확인" "ls $EXPORTS_FILE" "파일 없음"
fi
log_basis "[U_40_2] NFS 전체 호스트 허용 설정 여부" "$([[ $U_40_2 -eq 1 ]] && echo '취약' || echo '양호')"

if [[ $U_40_1 -eq 1 ]] || [[ $U_40_2 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_40_1": $U_40_1,
      "U_40_2": $U_40_2
    },
    "timestamp": "$DATE"
  }
}
EOF
