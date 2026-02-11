#!/bin/bash

# [U-31] 홈디렉토리 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-31"
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
U_31_1=0 
IS_VUL=0

# --- 점검 시작 ---
# 반복문 내 전수 조사를 로그로 남김
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    
    if [ ! -d "$HOMEDIR" ]; then
        continue
    fi

    if [[ "$HOMEDIR" == "/" || "$HOMEDIR" == "/bin" || "$HOMEDIR" == "/sbin" || "$HOMEDIR" == "/dev" || "$HOMEDIR" == "/proc" || "$HOMEDIR" == "/sys" ]]; then
        continue
    fi

    # 소유자 및 권한 확인 커맨드 로그 기록
    OWNER=$(run_cmd "[U_31_1] $USERNAME 홈 디렉터리 소유자 확인" "stat -c '%U' $HOMEDIR")
    PERM_STR=$(run_cmd "[U_31_1] $USERNAME 홈 디렉터리 권한 확인" "stat -c '%A' $HOMEDIR")

    # 진단 로직 유지
    if [ "$OWNER" != "$USERNAME" ]; then
        U_31_1=1
    fi

    OTHER_PERM=${PERM_STR:7:3}
    if [[ "$OTHER_PERM" == *"w"* ]]; then
        U_31_1=1
    fi

done < /etc/passwd

# --- 최종 결과 집계 ---
IS_VUL=$U_31_1

if [ $U_31_1 -eq 1 ]; then
    log_basis "[U_31_1] 소유자가 일치하지 않거나 Other 쓰기 권한이 부여된 홈 디렉터리 존재" "취약"
else
    log_basis "[U_31_1] 모든 홈 디렉터리의 소유자 및 권한 설정 양호" "양호"
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
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_31_1": $U_31_1
    },
    "timestamp": "$DATE"
  }
}
EOF
