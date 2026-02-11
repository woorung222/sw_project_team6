#!/bin/bash

# [U-15] 파일 및 디렉터리 소유자 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자(nouser) 또는 그룹(nogroup)이 존재하지 않는 파일이 발견되지 않으면 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-15"
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
U_15_1=0 
IS_VUL=0

# --- 점검 시작 ---

# find 명령어 옵션 설명:
# -nouser -o -nogroup : 소유자 없음 OR 그룹 없음
# run_cmd로 실행
CMD_FIND="find / -xdev \( -nouser -o -nogroup \) -print -quit 2>/dev/null"
FOUND_FILE=$(run_cmd "[U_15_1] 소유자/그룹 없는 파일 검색" "$CMD_FIND")

if [ -z "$FOUND_FILE" ]; then
    # 발견된 파일이 없음 (양호)
    U_15_1=0
    log_basis "[U_15_1] 소유자나 그룹이 없는 파일이 발견되지 않음" "양호"
else
    # 소유자 없는 파일이 존재함 (취약)
    U_15_1=1
    log_basis "[U_15_1] 소유자나 그룹이 없는 파일이 존재함: $FOUND_FILE 등" "취약"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_15_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-15",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_15_1": $U_15_1
    },
    "timestamp": "$DATE"
  }
}
EOF
