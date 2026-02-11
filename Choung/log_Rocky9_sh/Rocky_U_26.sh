#!/bin/bash

# [U-26] /dev에 존재하지 않는 device 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /dev 디렉터리 내에 불필요한 일반 파일(Regular File)이 존재하지 않으면 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-26"
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

# 초기 상태 설정
U_26_1=0 
IS_VUL=0

# --- 점검 시작 ---

# run_cmd 적용
# 이스케이프 주의: 괄호 \(\) -> \\( \\)
CMD_FIND="find /dev \\( -path '/dev/shm' -o -path '/dev/mqueue' -o -path '/dev/.udev' -o -path '/dev/fd' \\) -prune -o -type f -print 2>/dev/null"

FOUND_FILES=$(run_cmd "[U_26_1] /dev 내 일반 파일 검색" "$CMD_FIND")

if [ -z "$FOUND_FILES" ]; then
    U_26_1=0
    log_basis "[U_26_1] /dev 내 불필요한 일반 파일이 없음" "양호"
else
    U_26_1=1
    # 발견된 파일 중 첫 줄만 로그에 기록
    FIRST_FILE=$(echo "$FOUND_FILES" | head -n 1)
    log_basis "[U_26_1] /dev 내 일반 파일 발견: $FIRST_FILE 등" "취약"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_26_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-26",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_26_1": $U_26_1
    },
    "timestamp": "$DATE"
  }
}
EOF
