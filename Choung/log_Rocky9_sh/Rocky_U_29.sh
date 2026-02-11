#!/bin/bash

# [U-29] hosts.lpd 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 파일이 없거나, 소유자가 root이고 권한이 600 이하인 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-29"
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
U_29_1=0 
IS_VUL=0

# --- 점검 시작 ---
TARGET_FILE="/etc/hosts.lpd"

# [U_29_1] 파일 존재 확인부터 로그 기록
FILE_EXISTS=$(run_cmd "[U_29_1] 파일 존재 여부 확인" "ls -l $TARGET_FILE 2>/dev/null")

if [ ! -f "$TARGET_FILE" ]; then
    # 1. 파일이 존재하지 않음 (양호)
    U_29_1=0
    log_basis "[U_29_1] $TARGET_FILE 파일이 존재하지 않음" "양호"
else
    # 파일이 존재하는 경우 속성 점검 (전수 로그)
    OWNER=$(run_cmd "[U_29_1] 소유자 확인" "stat -c '%U' $TARGET_FILE")
    PERM=$(run_cmd "[U_29_1] 권한 확인" "stat -c '%a' $TARGET_FILE")

    # 진단 로직
    if [ "$OWNER" == "root" ] && [ "$PERM" -le 600 ]; then
        U_29_1=0
        log_basis "[U_29_1] 소유자(root) 및 권한($PERM) 양호" "양호"
    else
        U_29_1=1
        log_basis "[U_29_1] 소유자($OWNER) 또는 권한($PERM) 취약" "취약"
    fi
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_29_1

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
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_29_1": $U_29_1
    },
    "timestamp": "$DATE"
  }
}
EOF
