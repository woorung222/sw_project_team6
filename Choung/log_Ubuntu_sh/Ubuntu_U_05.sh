#!/bin/bash

# [U-05] root홈/패스 디렉터리 권한 및 PATH 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U_05"
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

# 초기화
U_05_1=1; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. root HOME 권한 점검
ROOT_HOME=$(getent passwd root | awk -F: '{print $6}')
RH_OWNER=$(run_cmd "[U_05_1] root 홈 디렉터리 소유자 확인" "stat -c '%U' '$ROOT_HOME'")
RH_PERM=$(run_cmd "[U_05_1] root 홈 디렉터리 권한 확인" "stat -c '%a' '$ROOT_HOME'")

# 2. PATH 문자열 점검 (마침표 및 빈 항목)
# stdout 노출 방지를 위해 변수에 담아 처리
BAD_PATH=$(run_cmd "[U_05_1] PATH 내 '.' 또는 빈 항목(::) 존재 확인" "echo \$PATH | awk -F: '{for(i=1;i<=NF;i++){if(\$i==\".\" || \$i==\"\"){print \"발견\";exit}}}'")

# 판정 로직: 소유자 root, group/other 쓰기(2) 권한 금지, PATH 내 위험 항목 없음
# 권한 예: 755(양호), 777(취약)
if [[ "$RH_OWNER" == "root" ]] && [[ ! "$RH_PERM" =~ [2367]$ ]] && [[ ! "$RH_PERM" =~ ^[0-9][2367][0-9]$ ]] && [[ "$BAD_PATH" != "발견" ]]; then
    U_05_1=0
    log_basis "[U_05_1] root 홈 디렉터리 권한 및 PATH 설정이 적절함" "양호"
else
    U_05_1=1
    log_basis "[U_05_1] root 홈 권한($RH_PERM) 미흡 또는 PATH 내 '.'/빈 항목 발견" "취약"
fi

IS_VUL=$U_05_1

# --- JSON 출력 (플래그 양식 고정) ---
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
    "category": "account",
    "flag": {
      "U_05_1": $U_05_1
    },
    "timestamp": "$DATE"
  }
}
EOF
