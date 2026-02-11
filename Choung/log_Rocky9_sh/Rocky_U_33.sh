#!/bin/bash

# [U-33] 숨겨진 파일 및 디렉토리 검색 및 제거 점검
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-33"
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
U_33_1=0 
IS_VUL=0

# --- 점검 시작 ---
CHECK_DIRS="/tmp /var/tmp /dev /run/shm"

# find 커맨드 실행 및 로그 기록
CMD_FIND="find $CHECK_DIRS -name '.*' ! -name '.' ! -name '..' 2>/dev/null | grep -vE '/dev/\.udev|/dev/\.blkid'"
FOUND_FILES=$(run_cmd "[U_33_1] 고위험 디렉터리 내 숨겨진 파일 검색" "$CMD_FIND")

if [ -z "$FOUND_FILES" ]; then
    U_33_1=0
    log_basis "[U_33_1] 주요 의심 경로에 불필요한 숨겨진 파일이 발견되지 않음" "양호"
else
    U_33_1=1
    # 발견된 파일 중 첫 번째만 로그에 요약 기록
    FIRST_HIDDEN=$(echo "$FOUND_FILES" | head -n 1)
    log_basis "[U_33_1] 의심스러운 숨겨진 파일 발견: $FIRST_HIDDEN 등" "취약"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_33_1

# --- JSON 출력 ---
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
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_33_1": $U_33_1
    },
    "timestamp": "$DATE"
  }
}
EOF
