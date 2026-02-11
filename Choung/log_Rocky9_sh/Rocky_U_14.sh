#!/bin/bash

# [U-14] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-14"
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
U_14_1=0 
IS_VUL=0

# --- 점검 시작 ---
# root 계정의 PATH 환경변수 확인
CURRENT_PATH=$PATH

# 점검 로직:
# echo와 grep을 이용한 검사를 run_cmd로 처리
# 파이프라인 내 특수문자 이스케이프 주의 (\\\\. 등)
CHECK_RESULT=$(run_cmd "[U_14_1] PATH 변수 내 '.' 포함 여부 확인" "echo '$CURRENT_PATH' | grep -E '^\.|:\.:'")

if [ -n "$CHECK_RESULT" ]; then
    # 취약 패턴 발견
    U_14_1=1
    IS_VUL=1
    log_basis "[U_14_1] PATH 환경변수 맨 앞 혹은 중간에 '.'이 포함됨" "취약"
else
    # 패턴 미발견 (양호)
    U_14_1=0
    IS_VUL=0
    log_basis "[U_14_1] PATH 환경변수에 안전하지 않은 경로(.)가 포함되지 않음" "양호"
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
    "flag_id": "U-14",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_14_1": $U_14_1
    },
    "timestamp": "$DATE"
  }
}
EOF
