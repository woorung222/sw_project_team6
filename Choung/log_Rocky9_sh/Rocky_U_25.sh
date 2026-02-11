#!/bin/bash

# [U-25] world writable 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 불필요한 world writable 파일(other에 쓰기 권한이 있는 파일)이 존재하면 취약

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-25"
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
U_25_1=0 
IS_VUL=0

# --- 점검 시작 ---
# run_cmd 적용: 검색 명령어 자체를 로그로 남김
CMD_FIND="find / -xdev -type f -perm -0002 -print -quit 2>/dev/null"
FOUND_FILE=$(run_cmd "[U_25_1] World Writable 파일 검색" "$CMD_FIND")

if [ -z "$FOUND_FILE" ]; then
    U_25_1=0
    log_basis "[U_25_1] World Writable 파일이 발견되지 않음" "양호"
else
    U_25_1=1
    log_basis "[U_25_1] World Writable 파일 발견: $FOUND_FILE 등" "취약"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_25_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-25",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_25_1": $U_25_1
    },
    "timestamp": "$DATE"
  }
}
EOF
