#!/bin/bash

# [U-32] 홈 디렉토리로 지정한 디렉토리의 존재 관리 점검
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-32"
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
U_32_1=0 
IS_VUL=0

# --- 점검 시작 ---
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    
    if [ ! -z "$HOMEDIR" ]; then
        # 존재 여부 확인 커맨드 로그 기록
        CHECK_DIR=$(run_cmd "[U_32_1] $USERNAME 홈 디렉터리 존재 확인" "ls -d $HOMEDIR 2>/dev/null")
        
        if [ ! -d "$HOMEDIR" ]; then
            U_32_1=1
        fi
    fi

done < /etc/passwd

# --- 최종 결과 집계 ---
IS_VUL=$U_32_1

if [ $U_32_1 -eq 1 ]; then
    log_basis "[U_32_1] /etc/passwd에 설정된 홈 디렉터리가 실제 존재하지 않는 계정이 발견됨" "취약"
else
    log_basis "[U_32_1] 모든 계정의 홈 디렉터리가 실제 시스템에 존재함" "양호"
fi

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
      "U_32_1": $U_32_1
    },
    "timestamp": "$DATE"
  }
}
EOF
