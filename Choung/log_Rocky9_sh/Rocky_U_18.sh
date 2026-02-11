#!/bin/bash

# [U-18] /etc/shadow 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자가 root이고, 권한이 400 이하인 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-18"
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
U_18_1=0 
IS_VUL=0

# --- 점검 시작 ---
TARGET_FILE="/etc/shadow"

if [ -f "$TARGET_FILE" ]; then
    # 1. 소유자 확인
    OWNER=$(run_cmd "[U_18_1] 파일 소유자 확인" "stat -c '%U' $TARGET_FILE")
    
    # 2. 권한 확인 (숫자 형태)
    PERM=$(run_cmd "[U_18_1] 파일 권한 확인" "stat -c '%a' $TARGET_FILE")

    # 진단 로직
    if [ "$OWNER" == "root" ] && [ "$PERM" -le 400 ]; then
        U_18_1=0
        log_basis "[U_18_1] 소유자(root) 및 권한($PERM)이 400 이하로 안전함" "양호"
    else
        # 소유자가 다르거나, 권한이 400을 초과함
        U_18_1=1
        log_basis "[U_18_1] 소유자($OWNER)가 root가 아니거나 권한($PERM)이 400을 초과함" "취약"
    fi
else
    U_18_1=1
    log_step "[U_18_1] 파일 존재 확인" "[ -f $TARGET_FILE ]" "파일 없음"
    log_basis "[U_18_1] /etc/shadow 파일이 존재하지 않음" "취약"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_18_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-18",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_18_1": $U_18_1
    },
    "timestamp": "$DATE"
  }
}
EOF
