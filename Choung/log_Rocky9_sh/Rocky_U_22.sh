#!/bin/bash

# [U-22] /etc/services 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-22"
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
U_22_1=0 
IS_VUL=0

# --- 점검 시작 ---
TARGET_FILE="/etc/services"

if [ -f "$TARGET_FILE" ]; then
    # 1. 소유자 확인
    OWNER=$(run_cmd "[U_22_1] 파일 소유자 확인" "stat -c '%U' $TARGET_FILE")
    
    # 2. 권한 확인 (숫자 형태)
    PERM=$(run_cmd "[U_22_1] 파일 권한 확인" "stat -c '%a' $TARGET_FILE")

    # 진단 로직
    OWNER_CHECK=0
    if [[ "$OWNER" == "root" || "$OWNER" == "bin" || "$OWNER" == "sys" ]]; then
        OWNER_CHECK=1
    fi
    
    if [ $OWNER_CHECK -eq 1 ] && [ "$PERM" -le 644 ]; then
        U_22_1=0
        log_basis "[U_22_1] 소유자($OWNER) 및 권한($PERM) 양호" "양호"
    else
        U_22_1=1
        log_basis "[U_22_1] 소유자($OWNER) 또는 권한($PERM) 취약" "취약"
    fi
else
    U_22_1=1
    log_step "[U_22_1] 파일 존재 확인" "[ -f $TARGET_FILE ]" "파일 없음"
    log_basis "[U_22_1] /etc/services 파일이 존재하지 않음" "취약"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_22_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-22",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_22_1": $U_22_1
    },
    "timestamp": "$DATE"
  }
}
EOF
