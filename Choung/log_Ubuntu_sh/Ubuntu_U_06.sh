#!/bin/bash

# [U-06] 파일 및 디렉터리 소유자 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-06"
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
U_06_1=1; IS_VUL=0

# --- 점검 로직 시작 ---

# 성능 및 안정성을 위해 제외할 경로 (Prune)
PRUNE_EXPR="-path /proc -prune -o -path /sys -prune -o -path /run -prune -o -path /dev -prune -o -path /var/lib/docker -prune"

# 1. 소유자 없는 파일 탐색 (nouser)
NOUSER_CHECK=$(run_cmd "[U_06_1] 소유자 없는 파일(nouser) 존재 여부 확인" "find / $PRUNE_EXPR -o -nouser -print -quit 2>/dev/null | grep -q '.' && echo '취약' || echo '양호'")

# 2. 소유 그룹 없는 파일 탐색 (nogroup)
NOGROUP_CHECK=$(run_cmd "[U_06_1] 소유 그룹 없는 파일(nogroup) 존재 여부 확인" "find / $PRUNE_EXPR -o -nogroup -print -quit 2>/dev/null | grep -q '.' && echo '취약' || echo '양호'")

if [[ "$NOUSER_CHECK" == "양호" ]] && [[ "$NOGROUP_CHECK" == "양호" ]]; then
    U_06_1=0
    log_basis "[U_06_1] 소유자 또는 그룹이 없는 파일이 발견되지 않음" "양호"
else
    U_06_1=1
    log_basis "[U_06_1] 시스템에 소유자(UID) 또는 그룹(GID)이 없는 파일이 존재함" "취약"
fi

IS_VUL=$U_06_1

# --- JSON 출력 (플래그 양식 고정) ---
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
      "U_06_1": $U_06_1
    },
    "timestamp": "$DATE"
  }
}
EOF
