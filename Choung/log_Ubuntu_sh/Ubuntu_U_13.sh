#!/bin/bash

# [U-13] SUID/SGID 설정 파일 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-13"
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
U_13_1=1; IS_VUL=0

# --- 점검 로직 시작 ---

# 성능 및 안정성을 위해 제외할 경로 (Ubuntu 특성 반영)
PRUNE_EXPR="-path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o -path /snap -prune -o -path /var/lib/docker -prune -o -path /var/lib/containerd -prune"

# 1. SUID/SGID 파일 탐색 (하나라도 발견 시 취약 간주 로직)
# find 명령 기록
FOUND_SUID=$(run_cmd "[U_13_1] SUID/SGID 파일 탐색 (최초 발견 시 종료)" "find / $PRUNE_EXPR -o -type f \( -perm -4000 -o -perm -2000 \) -print -quit 2>/dev/null")

if [[ -z "$FOUND_SUID" ]]; then
    U_13_1=0
    log_basis "[U_13_1] SUID/SGID 설정 파일이 발견되지 않음" "양호"
else
    U_13_1=1
    log_basis "[U_13_1] 시스템에 SUID/SGID 설정 파일이 존재함 (예: $FOUND_SUID)" "취약"
fi

IS_VUL=$U_13_1

# --- JSON 출력 (개행 양식 준수) ---
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
      "U_13_1": $U_13_1
    },
    "timestamp": "$DATE"
  }
}
EOF
